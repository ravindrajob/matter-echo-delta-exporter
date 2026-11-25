//! # `matter-echo-delta-exporter`
//!
//! Passive L4 Matter (`UDP/5540` MRP/CASE) & mDNS (`UDP/5353`) observer without decryption.
//! Measures `TX - RX Delta`, MRP retries, Matter Core Spec §4.11 Standalone ACKs, and RTT
//! histograms, exporting Prometheus `/metrics`, JSON `/api/status`, and a zero-CDN status UI.

pub mod config;
pub mod linux_capture;

use std::collections::{BTreeMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Default window (`1800 ms`) before an unanswered MRP burst increments Delta.
pub const DEFAULT_ACK_TIMEOUT_MS: u64 = 1_800;

/// Matter operational UDP port (CASE / MRP).
pub const MATTER_MRP_PORT: u16 = 5540;

/// Multicast DNS UDP port (`224.0.0.251:5353` / `[ff02::fb]:5353`).
pub const MDNS_PORT: u16 = 5353;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MonitoredPort {
    MatterMrp5540,
    Mdns5353,
}

impl MonitoredPort {
    pub fn from_ports(src_port: u16, dst_port: u16, matter_port: u16, mdns_port: u16) -> Option<Self> {
        if src_port == matter_port || dst_port == matter_port {
            Some(Self::MatterMrp5540)
        } else if src_port == mdns_port || dst_port == mdns_port {
            Some(Self::Mdns5353)
        } else {
            None
        }
    }

    pub fn prom_label(self) -> &'static str {
        match self {
            Self::MatterMrp5540 => "mrp_5540",
            Self::Mdns5353 => "mdns_5353",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedUdpFrame {
    pub timestamp_ms: u64,
    pub vlan_id: Option<u16>,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub port_class: MonitoredPort,
    pub udp_payload_len: usize,
    pub is_mdns_response: bool,
    pub contains_matter_mdns: bool,
}

/// Safe zero-copy Ethernet (`AF_PACKET`) parser supporting optional 802.1Q/QinQ VLAN tags,
/// IPv4 (`0x0800`), IPv6 (`0x86DD`), and UDP (`17`) headers on configured Matter & mDNS ports.
pub fn parse_af_packet_udp_frame(
    raw: &[u8],
    timestamp_ms: u64,
    matter_port: u16,
    mdns_port: u16,
) -> Option<DecodedUdpFrame> {
    if raw.len() < 14 {
        return None;
    }
    let mut ethertype = u16::from_be_bytes([raw[12], raw[13]]);
    let mut l3_offset = 14usize;
    let mut vlan_id = None;

    if ethertype == 0x8100 || ethertype == 0x88A8 {
        if raw.len() < 18 {
            return None;
        }
        let tci = u16::from_be_bytes([raw[14], raw[15]]);
        vlan_id = Some(tci & 0x0FFF);
        ethertype = u16::from_be_bytes([raw[16], raw[17]]);
        l3_offset = 18;
    }

    match ethertype {
        0x0800 => parse_ipv4_udp(&raw[l3_offset..], timestamp_ms, vlan_id, matter_port, mdns_port),
        0x86DD => parse_ipv6_udp(&raw[l3_offset..], timestamp_ms, vlan_id, matter_port, mdns_port),
        _ => None,
    }
}

fn parse_ipv4_udp(
    l3: &[u8],
    timestamp_ms: u64,
    vlan_id: Option<u16>,
    matter_port: u16,
    mdns_port: u16,
) -> Option<DecodedUdpFrame> {
    if l3.len() < 28 {
        return None;
    }
    let version = l3[0] >> 4;
    let ihl = ((l3[0] & 0x0F) as usize) * 4;
    if version != 4 || ihl < 20 || l3.len() < ihl + 8 || l3[9] != 17 {
        return None;
    }
    let frag = u16::from_be_bytes([l3[6], l3[7]]) & 0x1FFF;
    if frag != 0 {
        return None;
    }

    let src_ip = IpAddr::V4(Ipv4Addr::new(l3[12], l3[13], l3[14], l3[15]));
    let dst_ip = IpAddr::V4(Ipv4Addr::new(l3[16], l3[17], l3[18], l3[19]));
    parse_udp_segment(&l3[ihl..], src_ip, dst_ip, timestamp_ms, vlan_id, matter_port, mdns_port)
}

fn parse_ipv6_udp(
    l3: &[u8],
    timestamp_ms: u64,
    vlan_id: Option<u16>,
    matter_port: u16,
    mdns_port: u16,
) -> Option<DecodedUdpFrame> {
    if l3.len() < 48 || (l3[0] >> 4) != 6 || l3[6] != 17 {
        return None;
    }
    let mut src_octets = [0u8; 16];
    let mut dst_octets = [0u8; 16];
    src_octets.copy_from_slice(&l3[8..24]);
    dst_octets.copy_from_slice(&l3[24..40]);
    parse_udp_segment(
        &l3[40..],
        IpAddr::V6(Ipv6Addr::from(src_octets)),
        IpAddr::V6(Ipv6Addr::from(dst_octets)),
        timestamp_ms,
        vlan_id,
        matter_port,
        mdns_port,
    )
}

fn contains_ascii_case_insensitive(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|w| w.eq_ignore_ascii_case(needle))
}

fn parse_udp_segment(
    udp: &[u8],
    src_ip: IpAddr,
    dst_ip: IpAddr,
    timestamp_ms: u64,
    vlan_id: Option<u16>,
    matter_port: u16,
    mdns_port: u16,
) -> Option<DecodedUdpFrame> {
    if udp.len() < 8 {
        return None;
    }
    let src_port = u16::from_be_bytes([udp[0], udp[1]]);
    let dst_port = u16::from_be_bytes([udp[2], udp[3]]);
    let udp_len = u16::from_be_bytes([udp[4], udp[5]]) as usize;
    let port_class = MonitoredPort::from_ports(src_port, dst_port, matter_port, mdns_port)?;

    let payload = &udp[8..];
    let mut is_mdns_response = false;
    let mut contains_matter_mdns = false;
    if port_class == MonitoredPort::Mdns5353 && payload.len() >= 12 {
        let flags = u16::from_be_bytes([payload[2], payload[3]]);
        is_mdns_response = (flags & 0x8000) != 0;
        contains_matter_mdns = contains_ascii_case_insensitive(payload, b"_matter");
    }

    Some(DecodedUdpFrame {
        timestamp_ms,
        vlan_id,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        port_class,
        udp_payload_len: udp_len.saturating_sub(8),
        is_mdns_response,
        contains_matter_mdns,
    })
}

#[derive(Debug, Clone)]
pub struct RttHistogram {
    pub bounds_ms: [f64; 9],
    pub bucket_counts: [u64; 9],
    pub inf_count: u64,
    pub sum_ms: f64,
}

impl Default for RttHistogram {
    fn default() -> Self {
        Self {
            bounds_ms: [5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0, 1800.0],
            bucket_counts: [0; 9],
            inf_count: 0,
            sum_ms: 0.0,
        }
    }
}

impl RttHistogram {
    pub fn observe(&mut self, rtt_ms: f64) {
        for (idx, bound) in self.bounds_ms.iter().enumerate() {
            if rtt_ms <= *bound {
                self.bucket_counts[idx] += 1;
            }
        }
        self.inf_count += 1;
        self.sum_ms += rtt_ms;
    }

    pub fn count(&self) -> u64 {
        self.inf_count
    }

    pub fn sum_ms(&self) -> f64 {
        self.sum_ms
    }

    pub fn avg_ms(&self) -> f64 {
        if self.inf_count == 0 {
            0.0
        } else {
            self.sum_ms / (self.inf_count as f64)
        }
    }
}

#[derive(Debug, Clone)]
pub struct CorrelatorConfig {
    pub controllers: BTreeMap<IpAddr, String>,
    pub bridge_ip: IpAddr,
    pub ack_timeout_ms: u64,
    pub matter_port: u16,
    pub mdns_port: u16,
    pub standalone_ack_filter: bool,
    pub auto_discover_prefix: Option<String>,
}

impl CorrelatorConfig {
    pub fn new(bridge_ip: IpAddr, ack_timeout_ms: u64) -> Self {
        Self {
            controllers: BTreeMap::new(),
            bridge_ip,
            ack_timeout_ms,
            matter_port: MATTER_MRP_PORT,
            mdns_port: MDNS_PORT,
            standalone_ack_filter: true,
            auto_discover_prefix: None,
        }
    }

    pub fn with_controller(mut self, ip: IpAddr, label: &str) -> Self {
        self.controllers.insert(ip, label.to_string());
        self
    }
}

#[derive(Debug, Clone)]
struct PendingBurst {
    first_tx_ms: u64,
    last_tx_ms: u64,
    packets: u64,
    retries: u64,
}

#[derive(Debug, Default, Clone)]
pub struct FlowStats {
    pub echo_tx_packets_total: u64,
    pub bridge_rx_ack_total: u64,
    pub mrp_retries_total: u64,
    pub answered_bursts_total: u64,
    /// Filtered 1-packet, 0-retry Matter Core Spec §4.11 Standalone ACKs while bridge is UP.
    pub standalone_acks_total: u64,
    /// `Delta = Unanswered_Bursts` — MRP bursts exceeding `ack_timeout_ms` with zero Bridge ACK.
    pub unanswered_bursts_delta: u64,
    pub last_rtt_ms: f64,
    pub last_seen_ms: u64,
    pub consecutive_failure_streak: u64,
    pub rtt_histogram: RttHistogram,
}

#[derive(Debug, Clone)]
pub struct RecentEvent {
    pub ts_ms: u64,
    pub status: &'static str,
    pub proto: &'static str,
    pub controller: String,
    pub ip: String,
    pub packets: u64,
    pub retries: u64,
    pub rtt_ms: f64,
}

pub struct MatterEchoDeltaCorrelator {
    pub config: CorrelatorConfig,
    pub started_ms: u64,
    pub bridge_http_up: bool,
    in_flight: BTreeMap<(IpAddr, MonitoredPort), PendingBurst>,
    stats: BTreeMap<(IpAddr, MonitoredPort), FlowStats>,
    recent_events: VecDeque<RecentEvent>,
}

impl MatterEchoDeltaCorrelator {
    pub fn new(config: CorrelatorConfig, started_ms: u64) -> Self {
        let mut stats = BTreeMap::new();
        for &ctrl_ip in config.controllers.keys() {
            stats.insert((ctrl_ip, MonitoredPort::MatterMrp5540), FlowStats::default());
            stats.insert((ctrl_ip, MonitoredPort::Mdns5353), FlowStats::default());
        }
        Self {
            config,
            started_ms,
            bridge_http_up: true,
            in_flight: BTreeMap::new(),
            stats,
            recent_events: VecDeque::with_capacity(48),
        }
    }

    fn is_mdns_multicast(ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => v4 == Ipv4Addr::new(224, 0, 0, 251),
            IpAddr::V6(v6) => {
                v6.octets() == [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xfb]
            }
        }
    }

    fn is_tracked_controller(&mut self, ip: IpAddr) -> bool {
        if ip == self.config.bridge_ip {
            return false;
        }
        if self.config.controllers.contains_key(&ip) {
            return true;
        }
        if let Some(prefix) = &self.config.auto_discover_prefix {
            let ip_s = ip.to_string();
            if ip_s.starts_with(prefix) && self.config.controllers.len() < 128 {
                let slug = format!("peer-{}", ip_s.replace(['.', ':'], "-"));
                self.config.controllers.insert(ip, slug);
                self.stats
                    .entry((ip, MonitoredPort::MatterMrp5540))
                    .or_default();
                self.stats
                    .entry((ip, MonitoredPort::Mdns5353))
                    .or_default();
                return true;
            }
        }
        false
    }

    fn push_event(&mut self, ev: RecentEvent) {
        if self.recent_events.len() >= 40 {
            self.recent_events.pop_back();
        }
        self.recent_events.push_front(ev);
    }

    pub fn expire_overdue_bursts(&mut self, now_ms: u64) -> usize {
        let timeout = self.config.ack_timeout_ms;
        let expired_keys: Vec<(IpAddr, MonitoredPort)> = self
            .in_flight
            .iter()
            .filter(|(_, burst)| now_ms.saturating_sub(burst.first_tx_ms) > timeout)
            .map(|(k, _)| *k)
            .collect();

        let mut delta_count = 0usize;
        for key in expired_keys {
            let Some(burst) = self.in_flight.remove(&key) else {
                continue;
            };
            let (ip, proto) = key;
            let node = self.node_label(&ip);

            // Matter Core Spec §4.11: a single isolated UDP/5540 packet with 0 MRP retries
            // while the bridge HTTP endpoint is healthy is a Standalone ACK replying to an
            // unsolicited ReportData subscription push (expects no bridge reply).
            if proto == MonitoredPort::MatterMrp5540
                && self.config.standalone_ack_filter
                && burst.packets == 1
                && burst.retries == 0
                && self.bridge_http_up
            {
                let st = self.stats.entry(key).or_default();
                st.standalone_acks_total += 1;
                self.push_event(RecentEvent {
                    ts_ms: now_ms,
                    status: "standalone_ack",
                    proto: proto.prom_label(),
                    controller: node,
                    ip: ip.to_string(),
                    packets: 1,
                    retries: 0,
                    rtt_ms: 0.0,
                });
                continue;
            }

            let st = self.stats.entry(key).or_default();
            st.unanswered_bursts_delta += 1;
            st.consecutive_failure_streak += 1;
            delta_count += 1;
            self.push_event(RecentEvent {
                ts_ms: now_ms,
                status: "unanswered",
                proto: proto.prom_label(),
                controller: node,
                ip: ip.to_string(),
                packets: burst.packets,
                retries: burst.retries,
                rtt_ms: now_ms.saturating_sub(burst.first_tx_ms) as f64,
            });
        }
        delta_count
    }

    pub fn ingest_packet(&mut self, pkt: &DecodedUdpFrame) {
        self.expire_overdue_bursts(pkt.timestamp_ms);

        // 1. Controller TX -> Bridge (UDP/5540 or mDNS query UDP/5353)
        let is_mdns_query_to_bridge = pkt.port_class == MonitoredPort::Mdns5353
            && !pkt.is_mdns_response
            && (pkt.dst_ip == self.config.bridge_ip || Self::is_mdns_multicast(pkt.dst_ip));
        let is_matter_tx_to_bridge =
            pkt.port_class == MonitoredPort::MatterMrp5540 && pkt.dst_ip == self.config.bridge_ip;

        if (is_matter_tx_to_bridge || is_mdns_query_to_bridge) && self.is_tracked_controller(pkt.src_ip) {
            let key = (pkt.src_ip, pkt.port_class);
            let entry = self.stats.entry(key).or_default();
            entry.echo_tx_packets_total += 1;
            entry.last_seen_ms = pkt.timestamp_ms;

            if let Some(active) = self.in_flight.get_mut(&key) {
                active.packets += 1;
                active.retries += 1;
                active.last_tx_ms = pkt.timestamp_ms;
                entry.mrp_retries_total += 1;
            } else {
                self.in_flight.insert(
                    key,
                    PendingBurst {
                        first_tx_ms: pkt.timestamp_ms,
                        last_tx_ms: pkt.timestamp_ms,
                        packets: 1,
                        retries: 0,
                    },
                );
            }
            return;
        }

        // 2. Bridge RX ACK -> Controller (unicast reply or multicast mDNS announcement)
        if pkt.src_ip == self.config.bridge_ip {
            if self.is_tracked_controller(pkt.dst_ip) {
                self.complete_ack((pkt.dst_ip, pkt.port_class), pkt.timestamp_ms);
            } else if pkt.port_class == MonitoredPort::Mdns5353 && Self::is_mdns_multicast(pkt.dst_ip) {
                let waiting_mdns: Vec<IpAddr> = self
                    .in_flight
                    .keys()
                    .filter_map(|(ip, proto)| {
                        if *proto == MonitoredPort::Mdns5353 {
                            Some(*ip)
                        } else {
                            None
                        }
                    })
                    .collect();
                for ctrl_ip in waiting_mdns {
                    self.complete_ack((ctrl_ip, MonitoredPort::Mdns5353), pkt.timestamp_ms);
                }
            }
        }
    }

    fn complete_ack(&mut self, key: (IpAddr, MonitoredPort), ack_ts_ms: u64) {
        let (ip, proto) = key;
        let node = self.node_label(&ip);
        let stats = self.stats.entry(key).or_default();
        stats.bridge_rx_ack_total += 1;
        stats.last_seen_ms = ack_ts_ms;
        stats.consecutive_failure_streak = 0;

        if let Some(burst) = self.in_flight.remove(&key) {
            let rtt_ms = ack_ts_ms.saturating_sub(burst.first_tx_ms);
            if rtt_ms <= self.config.ack_timeout_ms {
                stats.answered_bursts_total += 1;
                stats.last_rtt_ms = rtt_ms as f64;
                stats.rtt_histogram.observe(rtt_ms as f64);
                self.push_event(RecentEvent {
                    ts_ms: ack_ts_ms,
                    status: "answered",
                    proto: proto.prom_label(),
                    controller: node,
                    ip: ip.to_string(),
                    packets: burst.packets,
                    retries: burst.retries,
                    rtt_ms: rtt_ms as f64,
                });
            } else {
                stats.unanswered_bursts_delta += 1;
                stats.consecutive_failure_streak += 1;
            }
        }
    }

    pub fn stats_for(&self, controller_ip: IpAddr, proto: MonitoredPort) -> Option<&FlowStats> {
        self.stats.get(&(controller_ip, proto))
    }

    pub fn is_silent_disconnect(&self, now_ms: u64) -> bool {
        let uptime_ms = now_ms.saturating_sub(self.started_ms);
        let total_replies: u64 = self
            .stats
            .iter()
            .filter(|((_, p), _)| *p == MonitoredPort::MatterMrp5540)
            .map(|(_, s)| s.bridge_rx_ack_total)
            .sum();
        let total_mdns: u64 = self
            .stats
            .iter()
            .filter(|((_, p), _)| *p == MonitoredPort::Mdns5353)
            .map(|(_, s)| s.echo_tx_packets_total)
            .sum();
        self.bridge_http_up && uptime_ms > 300_000 && total_replies == 0 && total_mdns > 0
    }

    pub fn render_prometheus_metrics(&self, now_ms: u64) -> String {
        let mut out = String::with_capacity(4096);
        let bridge_up = if self.bridge_http_up { 1 } else { 0 };
        let silent = if self.is_silent_disconnect(now_ms) { 1 } else { 0 };

        out.push_str("# HELP matter_bridge_http_up 1 if the Matter bridge HTTP endpoint responds, else 0.\n");
        out.push_str("# TYPE matter_bridge_http_up gauge\n");
        out.push_str(&format!("matter_bridge_http_up {bridge_up}\n"));

        out.push_str("# HELP matter_silent_disconnect 1 if bridge HTTP is UP >5m, mDNS queries arrive, and 0 Matter CASE replies occurred.\n");
        out.push_str("# TYPE matter_silent_disconnect gauge\n");
        out.push_str(&format!("matter_silent_disconnect {silent}\n"));

        out.push_str("# HELP matter_echo_tx_packets_total Total UDP 5540/5353 packets transmitted by Matter controller.\n");
        out.push_str("# TYPE matter_echo_tx_packets_total counter\n");
        for ((ip, proto), st) in &self.stats {
            let node = prom_escape(&self.node_label(ip));
            out.push_str(&format!(
                "matter_echo_tx_packets_total{{controller=\"{node}\",proto=\"{}\"}} {}\n",
                proto.prom_label(),
                st.echo_tx_packets_total
            ));
        }

        out.push_str("# HELP matter_bridge_rx_ack_total Total UDP 5540/5353 ACK packets returned by Matter bridge.\n");
        out.push_str("# TYPE matter_bridge_rx_ack_total counter\n");
        for ((ip, proto), st) in &self.stats {
            let node = prom_escape(&self.node_label(ip));
            out.push_str(&format!(
                "matter_bridge_rx_ack_total{{controller=\"{node}\",proto=\"{}\"}} {}\n",
                proto.prom_label(),
                st.bridge_rx_ack_total
            ));
        }

        out.push_str("# HELP matter_mrp_retries_total Intra-burst MRP/mDNS retransmissions prior to Bridge ACK or timeout.\n");
        out.push_str("# TYPE matter_mrp_retries_total counter\n");
        for ((ip, proto), st) in &self.stats {
            let node = prom_escape(&self.node_label(ip));
            out.push_str(&format!(
                "matter_mrp_retries_total{{controller=\"{node}\",proto=\"{}\"}} {}\n",
                proto.prom_label(),
                st.mrp_retries_total
            ));
        }

        out.push_str("# HELP matter_echo_answered_bursts_total Controller bursts acknowledged within ack_timeout_ms.\n");
        out.push_str("# TYPE matter_echo_answered_bursts_total counter\n");
        for ((ip, proto), st) in &self.stats {
            let node = prom_escape(&self.node_label(ip));
            out.push_str(&format!(
                "matter_echo_answered_bursts_total{{controller=\"{node}\",proto=\"{}\"}} {}\n",
                proto.prom_label(),
                st.answered_bursts_total
            ));
        }

        out.push_str("# HELP matter_echo_standalone_acks_total Filtered 1-packet Matter Core Spec §4.11 Standalone ACKs (0 retries, bridge UP).\n");
        out.push_str("# TYPE matter_echo_standalone_acks_total counter\n");
        for ((ip, proto), st) in &self.stats {
            if *proto != MonitoredPort::MatterMrp5540 {
                continue;
            }
            let node = prom_escape(&self.node_label(ip));
            out.push_str(&format!(
                "matter_echo_standalone_acks_total{{controller=\"{node}\",proto=\"mrp_5540\"}} {}\n",
                st.standalone_acks_total
            ));
        }

        out.push_str("# HELP matter_echo_delta_unanswered_bursts_total TX - RX Delta: controller bursts with zero Bridge_RX_ACK.\n");
        out.push_str("# TYPE matter_echo_delta_unanswered_bursts_total counter\n");
        for ((ip, proto), st) in &self.stats {
            let node = prom_escape(&self.node_label(ip));
            out.push_str(&format!(
                "matter_echo_delta_unanswered_bursts_total{{controller=\"{node}\",proto=\"{}\"}} {}\n",
                proto.prom_label(),
                st.unanswered_bursts_delta
            ));
        }

        out.push_str("# HELP matter_echo_last_rtt_ms Last measured Matter/mDNS request->ACK RTT in milliseconds.\n");
        out.push_str("# TYPE matter_echo_last_rtt_ms gauge\n");
        for ((ip, proto), st) in &self.stats {
            let node = prom_escape(&self.node_label(ip));
            out.push_str(&format!(
                "matter_echo_last_rtt_ms{{controller=\"{node}\",proto=\"{}\"}} {:.2}\n",
                proto.prom_label(),
                st.last_rtt_ms
            ));
        }

        out.push_str("# HELP matter_echo_consecutive_failure_streak Current consecutive unanswered burst streak per controller (resets to 0 on ACK).\n");
        out.push_str("# TYPE matter_echo_consecutive_failure_streak gauge\n");
        for ((ip, proto), st) in &self.stats {
            let node = prom_escape(&self.node_label(ip));
            out.push_str(&format!(
                "matter_echo_consecutive_failure_streak{{controller=\"{node}\",proto=\"{}\"}} {}\n",
                proto.prom_label(),
                st.consecutive_failure_streak
            ));
        }

        out.push_str("# HELP matter_echo_ack_rtt_ms End-to-end RTT histogram between Echo_TX burst start and Bridge_RX_ACK.\n");
        out.push_str("# TYPE matter_echo_ack_rtt_ms histogram\n");
        for ((ip, proto), st) in &self.stats {
            let node = prom_escape(&self.node_label(ip));
            let p_lbl = proto.prom_label();
            for (idx, bound) in st.rtt_histogram.bounds_ms.iter().enumerate() {
                out.push_str(&format!(
                    "matter_echo_ack_rtt_ms_bucket{{controller=\"{node}\",proto=\"{p_lbl}\",le=\"{bound:.0}\"}} {}\n",
                    st.rtt_histogram.bucket_counts[idx]
                ));
            }
            out.push_str(&format!(
                "matter_echo_ack_rtt_ms_bucket{{controller=\"{node}\",proto=\"{p_lbl}\",le=\"+Inf\"}} {}\n",
                st.rtt_histogram.inf_count
            ));
            out.push_str(&format!(
                "matter_echo_ack_rtt_ms_sum{{controller=\"{node}\",proto=\"{p_lbl}\"}} {:.2}\n",
                st.rtt_histogram.sum_ms
            ));
            out.push_str(&format!(
                "matter_echo_ack_rtt_ms_count{{controller=\"{node}\",proto=\"{p_lbl}\"}} {}\n",
                st.rtt_histogram.inf_count
            ));
        }

        out
    }

    pub fn render_status_json(
        &self,
        now_ms: u64,
        mode: &str,
        iface: &str,
        bpf_attached: bool,
        caps_dropped: bool,
    ) -> String {
        let mut tot_answered = 0u64;
        let mut tot_delta = 0u64;
        let mut tot_retries = 0u64;
        let mut tot_standalone = 0u64;
        let mut rtt_sum = 0.0f64;
        let mut rtt_cnt = 0u64;
        let mut hist_totals = [0u64; 9];

        let mut ctrls_json = Vec::new();
        for (&ip, label) in &self.config.controllers {
            let mrp = self
                .stats
                .get(&(ip, MonitoredPort::MatterMrp5540))
                .cloned()
                .unwrap_or_default();
            let mdns = self
                .stats
                .get(&(ip, MonitoredPort::Mdns5353))
                .cloned()
                .unwrap_or_default();

            tot_answered += mrp.answered_bursts_total;
            tot_delta += mrp.unanswered_bursts_delta;
            tot_retries += mrp.mrp_retries_total;
            tot_standalone += mrp.standalone_acks_total;
            rtt_sum += mrp.rtt_histogram.sum_ms;
            rtt_cnt += mrp.rtt_histogram.inf_count;
            for (i, v) in mrp.rtt_histogram.bucket_counts.iter().enumerate() {
                hist_totals[i] += *v;
            }

            ctrls_json.push(format!(
                "{{\"controller\":{},\"ip\":{},\"tx_packets\":{},\"rx_acks\":{},\"answered\":{},\"delta\":{},\"retries\":{},\"standalone_acks\":{},\"last_rtt_ms\":{:.2},\"avg_rtt_ms\":{:.2},\"streak\":{},\"mdns_queries\":{},\"mdns_unanswered\":{}}}",
                json_str(label),
                json_str(&ip.to_string()),
                mrp.echo_tx_packets_total,
                mrp.bridge_rx_ack_total,
                mrp.answered_bursts_total,
                mrp.unanswered_bursts_delta,
                mrp.mrp_retries_total,
                mrp.standalone_acks_total,
                mrp.last_rtt_ms,
                mrp.rtt_histogram.avg_ms(),
                mrp.consecutive_failure_streak,
                mdns.echo_tx_packets_total,
                mdns.unanswered_bursts_delta
            ));
        }

        // Convert cumulative buckets to per-bucket deltas for clean UI bar chart
        let bounds = [5, 10, 25, 50, 100, 250, 500, 1000, 1800];
        let mut buckets_json = Vec::with_capacity(9);
        let mut prev = 0u64;
        for (i, b) in bounds.iter().enumerate() {
            let count = hist_totals[i].saturating_sub(prev);
            prev = hist_totals[i];
            buckets_json.push(format!("{{\"le_ms\":{b},\"count\":{count}}}"));
        }

        let events_json: Vec<String> = self
            .recent_events
            .iter()
            .take(12)
            .map(|e| {
                format!(
                    "{{\"ts_ms\":{},\"status\":{},\"proto\":{},\"controller\":{},\"ip\":{},\"packets\":{},\"retries\":{},\"rtt_ms\":{:.1}}}",
                    e.ts_ms,
                    json_str(e.status),
                    json_str(e.proto),
                    json_str(&e.controller),
                    json_str(&e.ip),
                    e.packets,
                    e.retries,
                    e.rtt_ms
                )
            })
            .collect();

        let avg_rtt = if rtt_cnt > 0 {
            rtt_sum / (rtt_cnt as f64)
        } else {
            0.0
        };
        let uptime_secs = now_ms.saturating_sub(self.started_ms) / 1000;

        format!(
            "{{\"version\":{},\"mode\":{},\"interface\":{},\"bridge_ip\":{},\"bridge_http_up\":{},\"silent_disconnect\":{},\"bpf_attached\":{},\"caps_dropped\":{},\"ack_timeout_ms\":{},\"standalone_ack_filter\":{},\"uptime_secs\":{},\"summary\":{{\"answered_bursts\":{},\"unanswered_delta\":{},\"mrp_retries\":{},\"standalone_acks\":{},\"avg_rtt_ms\":{:.2}}},\"rtt_buckets\":[{}],\"controllers\":[{}],\"recent_events\":[{}]}}",
            json_str(env!("CARGO_PKG_VERSION")),
            json_str(mode),
            json_str(iface),
            json_str(&self.config.bridge_ip.to_string()),
            self.bridge_http_up,
            self.is_silent_disconnect(now_ms),
            bpf_attached,
            caps_dropped,
            self.config.ack_timeout_ms,
            self.config.standalone_ack_filter,
            uptime_secs,
            tot_answered,
            tot_delta,
            tot_retries,
            tot_standalone,
            avg_rtt,
            buckets_json.join(","),
            ctrls_json.join(","),
            events_json.join(",")
        )
    }

    fn node_label(&self, ip: &IpAddr) -> String {
        self.config
            .controllers
            .get(ip)
            .cloned()
            .unwrap_or_else(|| ip.to_string())
    }
}

pub fn prom_escape(val: &str) -> String {
    val.replace('\\', "\\\\")
        .replace('\n', " ")
        .replace('"', "\\\"")
}

pub fn json_str(val: &str) -> String {
    let mut out = String::with_capacity(val.len() + 2);
    out.push('"');
    for ch in val.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_ipv4_eth_udp_frame(
        src: [u8; 4],
        dst: [u8; 4],
        src_port: u16,
        dst_port: u16,
        vlan: Option<u16>,
    ) -> Vec<u8> {
        let mut frame = Vec::new();
        frame.extend_from_slice(&[0x00, 0x00, 0x5e, 0x00, 0x53, 0x01]);
        frame.extend_from_slice(&[0x00, 0x00, 0x5e, 0x00, 0x53, 0x02]);
        if let Some(vid) = vlan {
            frame.extend_from_slice(&0x8100u16.to_be_bytes());
            frame.extend_from_slice(&vid.to_be_bytes());
        }
        frame.extend_from_slice(&0x0800u16.to_be_bytes());

        let total_len = 20u16 + 20u16;
        frame.push(0x45);
        frame.push(0x00);
        frame.extend_from_slice(&total_len.to_be_bytes());
        frame.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]);
        frame.push(64);
        frame.push(17);
        frame.extend_from_slice(&[0x00, 0x00]);
        frame.extend_from_slice(&src);
        frame.extend_from_slice(&dst);

        frame.extend_from_slice(&src_port.to_be_bytes());
        frame.extend_from_slice(&dst_port.to_be_bytes());
        frame.extend_from_slice(&20u16.to_be_bytes());
        frame.extend_from_slice(&[0x00, 0x00]);
        frame.extend_from_slice(&[0u8; 12]);
        frame
    }

    #[test]
    fn parses_tagged_vlan_and_ignores_non_matter_ports() {
        let raw_mrp =
            build_ipv4_eth_udp_frame([192, 0, 2, 10], [198, 51, 100, 20], 5540, 5540, Some(30));
        let parsed = parse_af_packet_udp_frame(&raw_mrp, 1_000, 5540, 5353).unwrap();
        assert_eq!(parsed.vlan_id, Some(30));
        assert_eq!(parsed.port_class, MonitoredPort::MatterMrp5540);
        assert_eq!(parsed.udp_payload_len, 12);

        let raw_ntp = build_ipv4_eth_udp_frame([192, 0, 2, 10], [198, 51, 100, 20], 123, 123, None);
        assert!(parse_af_packet_udp_frame(&raw_ntp, 1_100, 5540, 5353).is_none());
    }

    #[test]
    fn correlates_mrp_retries_and_ack_within_1800ms() {
        let echo_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        let bridge_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20));
        let cfg = CorrelatorConfig::new(bridge_ip, DEFAULT_ACK_TIMEOUT_MS)
            .with_controller(echo_ip, "echo-kitchen");
        let mut corr = MatterEchoDeltaCorrelator::new(cfg, 0);

        let tx1 = parse_af_packet_udp_frame(
            &build_ipv4_eth_udp_frame([192, 0, 2, 10], [198, 51, 100, 20], 5540, 5540, None),
            1_000,
            5540,
            5353,
        )
        .unwrap();
        let tx_retry = parse_af_packet_udp_frame(
            &build_ipv4_eth_udp_frame([192, 0, 2, 10], [198, 51, 100, 20], 5540, 5540, None),
            1_220,
            5540,
            5353,
        )
        .unwrap();
        let ack = parse_af_packet_udp_frame(
            &build_ipv4_eth_udp_frame([198, 51, 100, 20], [192, 0, 2, 10], 5540, 5540, None),
            1_340,
            5540,
            5353,
        )
        .unwrap();

        corr.ingest_packet(&tx1);
        corr.ingest_packet(&tx_retry);
        corr.ingest_packet(&ack);

        let st = corr.stats_for(echo_ip, MonitoredPort::MatterMrp5540).unwrap();
        assert_eq!(st.echo_tx_packets_total, 2);
        assert_eq!(st.mrp_retries_total, 1);
        assert_eq!(st.answered_bursts_total, 1);
        assert_eq!(st.unanswered_bursts_delta, 0);
        assert!((st.rtt_histogram.sum_ms() - 340.0).abs() < 1e-6);
    }

    #[test]
    fn filters_matter_spec_4_11_standalone_ack_when_bridge_up() {
        let echo_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        let bridge_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20));
        let cfg = CorrelatorConfig::new(bridge_ip, DEFAULT_ACK_TIMEOUT_MS)
            .with_controller(echo_ip, "echo-living");
        let mut corr = MatterEchoDeltaCorrelator::new(cfg, 0);

        // Single packet, 0 MRP retries, bridge UP -> Standalone ACK (NOT an alert)
        let pkt = parse_af_packet_udp_frame(
            &build_ipv4_eth_udp_frame([192, 0, 2, 10], [198, 51, 100, 20], 5540, 5540, None),
            5_000,
            5540,
            5353,
        )
        .unwrap();
        corr.ingest_packet(&pkt);
        let expired_deltas = corr.expire_overdue_bursts(7_000);
        assert_eq!(expired_deltas, 0);

        let st = corr.stats_for(echo_ip, MonitoredPort::MatterMrp5540).unwrap();
        assert_eq!(st.standalone_acks_total, 1);
        assert_eq!(st.unanswered_bursts_delta, 0);
    }

    #[test]
    fn counts_unanswered_delta_on_mrp_retransmission_burst() {
        let echo_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        let bridge_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20));
        let cfg = CorrelatorConfig::new(bridge_ip, DEFAULT_ACK_TIMEOUT_MS)
            .with_controller(echo_ip, "echo-kitchen");
        let mut corr = MatterEchoDeltaCorrelator::new(cfg, 0);

        for ts in [5_000u64, 5_350, 5_850] {
            let pkt = parse_af_packet_udp_frame(
                &build_ipv4_eth_udp_frame([192, 0, 2, 10], [198, 51, 100, 20], 5540, 5540, None),
                ts,
                5540,
                5353,
            )
            .unwrap();
            corr.ingest_packet(&pkt);
        }
        assert_eq!(corr.expire_overdue_bursts(7_000), 1);

        let st = corr.stats_for(echo_ip, MonitoredPort::MatterMrp5540).unwrap();
        assert_eq!(st.unanswered_bursts_delta, 1);
        assert_eq!(st.mrp_retries_total, 2);
        assert_eq!(st.consecutive_failure_streak, 1);

        let prom = corr.render_prometheus_metrics(7_000);
        assert!(prom.contains("matter_echo_delta_unanswered_bursts_total{controller=\"echo-kitchen\",proto=\"mrp_5540\"} 1"));
    }
}
