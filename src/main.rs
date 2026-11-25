use matter_echo_delta_exporter::config::AppConfig;
use matter_echo_delta_exporter::{
    parse_af_packet_udp_frame, CorrelatorConfig, DecodedUdpFrame, MatterEchoDeltaCorrelator,
    MonitoredPort, DEFAULT_ACK_TIMEOUT_MS, MATTER_MRP_PORT, MDNS_PORT,
};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const INDEX_HTML: &str = include_str!("ui/index.html");

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn build_demo_correlator() -> MatterEchoDeltaCorrelator {
    let bridge = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20));
    let mdns_mcast = IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251));
    let living = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
    let kitchen = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11));
    let bedroom = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 12));
    let office = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 13));

    let cfg = CorrelatorConfig::new(bridge, DEFAULT_ACK_TIMEOUT_MS)
        .with_controller(living, "echo-living")
        .with_controller(kitchen, "echo-kitchen")
        .with_controller(bedroom, "echo-bedroom")
        .with_controller(office, "homepod-office");

    let base_ts = now_ms().saturating_sub(180_000);
    let mut corr = MatterEchoDeltaCorrelator::new(cfg, base_ts);

    // 1. Healthy mDNS resolutions + fast LAN Matter CASE exchanges
    let healthy_samples = [
        (living, 1_000u64, 3u64),
        (living, 12_000, 2),
        (living, 28_000, 4),
        (living, 54_000, 3),
        (kitchen, 4_000, 7),
        (kitchen, 19_000, 12),
        (kitchen, 42_000, 18),
        (bedroom, 9_000, 5),
        (bedroom, 31_000, 8),
        (office, 6_000, 1),
        (office, 22_000, 2),
        (office, 61_000, 2),
    ];

    for (ctrl, offset, rtt) in healthy_samples {
        let t = base_ts + offset;
        corr.ingest_packet(&DecodedUdpFrame {
            timestamp_ms: t,
            vlan_id: Some(20),
            src_ip: ctrl,
            dst_ip: bridge,
            src_port: MATTER_MRP_PORT,
            dst_port: MATTER_MRP_PORT,
            port_class: MonitoredPort::MatterMrp5540,
            udp_payload_len: 92,
            is_mdns_response: false,
            contains_matter_mdns: false,
        });
        corr.ingest_packet(&DecodedUdpFrame {
            timestamp_ms: t + rtt,
            vlan_id: Some(20),
            src_ip: bridge,
            dst_ip: ctrl,
            src_port: MATTER_MRP_PORT,
            dst_port: MATTER_MRP_PORT,
            port_class: MonitoredPort::MatterMrp5540,
            udp_payload_len: 48,
            is_mdns_response: false,
            contains_matter_mdns: false,
        });
    }

    // 2. mDNS _matter operational query + reply
    for (ctrl, offset) in [(living, 2_000u64), (kitchen, 2_500), (office, 3_000)] {
        let t = base_ts + offset;
        corr.ingest_packet(&DecodedUdpFrame {
            timestamp_ms: t,
            vlan_id: Some(20),
            src_ip: ctrl,
            dst_ip: mdns_mcast,
            src_port: MDNS_PORT,
            dst_port: MDNS_PORT,
            port_class: MonitoredPort::Mdns5353,
            udp_payload_len: 68,
            is_mdns_response: false,
            contains_matter_mdns: true,
        });
        corr.ingest_packet(&DecodedUdpFrame {
            timestamp_ms: t + 11,
            vlan_id: Some(20),
            src_ip: bridge,
            dst_ip: mdns_mcast,
            src_port: MDNS_PORT,
            dst_port: MDNS_PORT,
            port_class: MonitoredPort::Mdns5353,
            udp_payload_len: 144,
            is_mdns_response: true,
            contains_matter_mdns: true,
        });
    }

    // 3. Matter Core Spec §4.11 Standalone ACKs (filtered cleanly, 0 false alerts)
    for (ctrl, offset) in [(living, 70_000u64), (bedroom, 75_000), (office, 80_000)] {
        let t = base_ts + offset;
        corr.ingest_packet(&DecodedUdpFrame {
            timestamp_ms: t,
            vlan_id: Some(20),
            src_ip: ctrl,
            dst_ip: bridge,
            src_port: MATTER_MRP_PORT,
            dst_port: MATTER_MRP_PORT,
            port_class: MonitoredPort::MatterMrp5540,
            udp_payload_len: 36,
            is_mdns_response: false,
            contains_matter_mdns: false,
        });
        corr.expire_overdue_bursts(t + 2_200);
    }

    // 4. Slow MRP burst with 1 retransmission recovered at 185 ms on echo-bedroom
    let t_slow = base_ts + 95_000;
    for delta in [0u64, 130] {
        corr.ingest_packet(&DecodedUdpFrame {
            timestamp_ms: t_slow + delta,
            vlan_id: Some(20),
            src_ip: bedroom,
            dst_ip: bridge,
            src_port: MATTER_MRP_PORT,
            dst_port: MATTER_MRP_PORT,
            port_class: MonitoredPort::MatterMrp5540,
            udp_payload_len: 92,
            is_mdns_response: false,
            contains_matter_mdns: false,
        });
    }
    corr.ingest_packet(&DecodedUdpFrame {
        timestamp_ms: t_slow + 185,
        vlan_id: Some(20),
        src_ip: bridge,
        dst_ip: bedroom,
        src_port: MATTER_MRP_PORT,
        dst_port: MATTER_MRP_PORT,
        port_class: MonitoredPort::MatterMrp5540,
        udp_payload_len: 48,
        is_mdns_response: false,
        contains_matter_mdns: false,
    });

    // 5. Real unanswered Matter MRP burst on echo-kitchen (3 packets, 2 retries, 0 ACK -> Delta = 1)
    let t_fail = base_ts + 130_000;
    for delta in [0u64, 380, 920] {
        corr.ingest_packet(&DecodedUdpFrame {
            timestamp_ms: t_fail + delta,
            vlan_id: Some(20),
            src_ip: kitchen,
            dst_ip: bridge,
            src_port: MATTER_MRP_PORT,
            dst_port: MATTER_MRP_PORT,
            port_class: MonitoredPort::MatterMrp5540,
            udp_payload_len: 92,
            is_mdns_response: false,
            contains_matter_mdns: false,
        });
    }
    corr.expire_overdue_bursts(t_fail + 2_100);
    corr
}

/// Minimal pure-std HTTP GET probe for local Matter Bridge health (e.g. `http://127.0.0.1:8482/`).
fn probe_http_health(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("http://") else {
        return true;
    };
    let (host_port, path) = match rest.find('/') {
        Some(idx) => (&rest[..idx], &rest[idx..]),
        None => (rest, "/"),
    };
    let addr = if host_port.contains(':') {
        host_port.to_string()
    } else {
        format!("{host_port}:80")
    };
    let Ok(mut addrs) = addr.to_socket_addrs() else {
        return false;
    };
    let Some(sock_addr) = addrs.next() else {
        return false;
    };
    let Ok(mut stream) = TcpStream::connect_timeout(&sock_addr, Duration::from_secs(2)) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
    let req = format!("GET {path} HTTP/1.1\r\nHost: {host_port}\r\nConnection: close\r\n\r\n");
    if stream.write_all(req.as_bytes()).is_err() {
        return false;
    }
    let mut buf = [0u8; 64];
    let Ok(n) = stream.read(&mut buf) else {
        return false;
    };
    let line = String::from_utf8_lossy(&buf[..n]);
    line.starts_with("HTTP/1.1 2")
        || line.starts_with("HTTP/1.1 3")
        || line.starts_with("HTTP/1.1 4")
        || line.starts_with("HTTP/1.0 2")
}

fn write_http_response(
    stream: &mut TcpStream,
    status: &str,
    content_type: &str,
    body: &[u8],
) -> std::io::Result<()> {
    let header = format!(
        "HTTP/1.1 {status}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {}\r\n\
         X-Content-Type-Options: nosniff\r\n\
         X-Frame-Options: DENY\r\n\
         Referrer-Policy: no-referrer\r\n\
         Cache-Control: no-store\r\n\
         Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'\r\n\
         Connection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()
}

fn handle_client(
    mut stream: TcpStream,
    correlator: &Arc<Mutex<MatterEchoDeltaCorrelator>>,
    cfg: &AppConfig,
    bpf_attached: bool,
    caps_dropped: bool,
) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
    let mut req_buf = [0u8; 2048];
    let n = match stream.read(&mut req_buf) {
        Ok(n) if n > 0 => n,
        _ => return,
    };
    let req_str = String::from_utf8_lossy(&req_buf[..n]);
    let first_line = req_str.lines().next().unwrap_or("");
    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let raw_path = parts.next().unwrap_or("/");
    let path = raw_path.split('?').next().unwrap_or("/");

    if method != "GET" && method != "HEAD" {
        let _ = write_http_response(&mut stream, "405 Method Not Allowed", "text/plain", b"Method Not Allowed\n");
        return;
    }

    let ts = now_ms();
    match path {
        "/metrics" => {
            let body = {
                let mut guard = match correlator.lock() {
                    Ok(g) => g,
                    Err(_) => return,
                };
                guard.expire_overdue_bursts(ts);
                guard.render_prometheus_metrics(ts)
            };
            let _ = write_http_response(
                &mut stream,
                "200 OK",
                "text/plain; version=0.0.4; charset=utf-8",
                if method == "HEAD" { b"" } else { body.as_bytes() },
            );
        }
        "/api/status" => {
            let mode = if cfg.demo_mode { "demo" } else { "live-bpf" };
            let body = {
                let mut guard = match correlator.lock() {
                    Ok(g) => g,
                    Err(_) => return,
                };
                guard.expire_overdue_bursts(ts);
                guard.render_status_json(ts, mode, &cfg.interface, bpf_attached, caps_dropped)
            };
            let _ = write_http_response(
                &mut stream,
                "200 OK",
                "application/json; charset=utf-8",
                if method == "HEAD" { b"" } else { body.as_bytes() },
            );
        }
        "/healthz" => {
            let _ = write_http_response(
                &mut stream,
                "200 OK",
                "application/json; charset=utf-8",
                br#"{"ok":true,"service":"matter-echo-delta-exporter"}"#,
            );
        }
        "/" if cfg.enable_ui => {
            let _ = write_http_response(
                &mut stream,
                "200 OK",
                "text/html; charset=utf-8",
                if method == "HEAD" { b"" } else { INDEX_HTML.as_bytes() },
            );
        }
        _ => {
            let _ = write_http_response(&mut stream, "404 Not Found", "text/plain", b"Not Found\n");
        }
    }
}

fn main() -> std::io::Result<()> {
    let cfg = AppConfig::load();

    if cfg.dump_once {
        let corr = build_demo_correlator();
        let out = corr.render_prometheus_metrics(now_ms());
        let _ = std::io::stdout().write_all(out.as_bytes());
        return Ok(());
    }

    let correlator = if cfg.demo_mode {
        Arc::new(Mutex::new(build_demo_correlator()))
    } else {
        Arc::new(Mutex::new(MatterEchoDeltaCorrelator::new(
            cfg.to_correlator_config(),
            now_ms(),
        )))
    };

    let bpf_attached = Arc::new(AtomicBool::new(false));
    let caps_dropped = Arc::new(AtomicBool::new(false));

    // Background timeout sweeper & optional Matter bridge HTTP health check
    {
        let corr_bg = Arc::clone(&correlator);
        let health_url = cfg.bridge_health_url.clone();
        let demo = cfg.demo_mode;
        thread::spawn(move || {
            let mut last_hc = 0u64;
            loop {
                thread::sleep(Duration::from_millis(250));
                let ts = now_ms();
                if !demo {
                    if let Some(url) = &health_url {
                        if ts.saturating_sub(last_hc) >= 10_000 {
                            let up = probe_http_health(url);
                            if let Ok(mut g) = corr_bg.lock() {
                                g.bridge_http_up = up;
                            }
                            last_hc = ts;
                        }
                    }
                }
                if let Ok(mut g) = corr_bg.lock() {
                    g.expire_overdue_bursts(ts);
                }
            }
        });
    }

    // Live Linux kernel BPF capture thread (skipped in --demo mode)
    #[cfg(target_os = "linux")]
    if !cfg.demo_mode {
        match matter_echo_delta_exporter::linux_capture::LinuxBpfSniffer::open(
            &cfg.interface,
            cfg.matter_port,
            cfg.mdns_port,
            cfg.drop_privileges_after_bpf,
        ) {
            Ok(sniffer) => {
                bpf_attached.store(sniffer.bpf_attached, Ordering::Relaxed);
                caps_dropped.store(sniffer.caps_dropped, Ordering::Relaxed);
                eprintln!(
                    "[matter-echo-delta] LIVE AF_PACKET sniffer on {} (BPF={}, caps_dropped={}, Matter=UDP/{}, mDNS=UDP/{})",
                    cfg.interface,
                    sniffer.bpf_attached,
                    sniffer.caps_dropped,
                    cfg.matter_port,
                    cfg.mdns_port
                );
                let corr_rx = Arc::clone(&correlator);
                let mp = cfg.matter_port;
                let dp = cfg.mdns_port;
                thread::spawn(move || {
                    let mut buf = [0u8; 512];
                    loop {
                        match sniffer.recv_frame(&mut buf) {
                            Ok(n) if n >= 42 => {
                                if let Some(pkt) = parse_af_packet_udp_frame(&buf[..n], now_ms(), mp, dp) {
                                    if let Ok(mut g) = corr_rx.lock() {
                                        g.ingest_packet(&pkt);
                                    }
                                }
                            }
                            Ok(_) => {}
                            Err(e) => {
                                eprintln!("[matter-echo-delta] capture error: {e}");
                                thread::sleep(Duration::from_millis(200));
                            }
                        }
                    }
                });
            }
            Err(e) => {
                eprintln!(
                    "[matter-echo-delta] FATAL: cannot open AF_PACKET on '{}' ({e}). Grant CAP_NET_RAW or run with --demo.",
                    cfg.interface
                );
                std::process::exit(1);
            }
        }
    }

    let listener = TcpListener::bind(&cfg.bind_addr)?;
    eprintln!(
        "[matter-echo-delta] v{} listening on http://{} (mode={}, config={})",
        env!("CARGO_PKG_VERSION"),
        cfg.bind_addr,
        if cfg.demo_mode { "demo" } else { "live-bpf" },
        cfg.config_path.as_deref().unwrap_or("defaults/env")
    );

    for incoming in listener.incoming() {
        if let Ok(stream) = incoming {
            let corr = Arc::clone(&correlator);
            let cfg_c = cfg.clone();
            let bpf_ok = bpf_attached.load(Ordering::Relaxed);
            let caps_ok = caps_dropped.load(Ordering::Relaxed);
            thread::spawn(move || handle_client(stream, &corr, &cfg_c, bpf_ok, caps_ok));
        }
    }

    Ok(())
}
