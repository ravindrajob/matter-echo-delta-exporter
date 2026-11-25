//! Pure-Rust zero-dependency `config.yaml` loader.
//!
//! Precedence (lowest -> highest):
//!   1. Safe defaults (`bind = 127.0.0.1:9124`, `ack_timeout_ms = 1800`, `standalone_ack_filter = true`)
//!   2. `config.yaml` (supports `#` comments, 2-space blocks, `${ENV_VAR}` expansion)
//!   3. Environment variables (`MATTER_SNIFF_IFACE`, `MATTER_BRIDGE_IP`, `MATTER_BIND`, ...)
//!   4. CLI flags (`--config`, `--demo`, `--bind`, `--iface`, `--bridge-ip`, `--once`)

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;

use crate::{CorrelatorConfig, DEFAULT_ACK_TIMEOUT_MS, MATTER_MRP_PORT, MDNS_PORT};

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub config_path: Option<String>,
    pub demo_mode: bool,
    pub dump_once: bool,
    pub interface: String,
    pub matter_port: u16,
    pub mdns_port: u16,
    pub drop_privileges_after_bpf: bool,
    pub bridge_ip: IpAddr,
    pub bridge_health_url: Option<String>,
    pub ack_timeout_ms: u64,
    pub standalone_ack_filter: bool,
    pub bind_addr: String,
    pub enable_ui: bool,
    pub auto_discover_prefix: Option<String>,
    pub controllers: BTreeMap<IpAddr, String>,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            config_path: None,
            demo_mode: false,
            dump_once: false,
            interface: "eth0".to_string(),
            matter_port: MATTER_MRP_PORT,
            mdns_port: MDNS_PORT,
            drop_privileges_after_bpf: true,
            bridge_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
            bridge_health_url: None,
            ack_timeout_ms: DEFAULT_ACK_TIMEOUT_MS,
            standalone_ack_filter: true,
            bind_addr: "127.0.0.1:9124".to_string(),
            enable_ui: true,
            auto_discover_prefix: None,
            controllers: BTreeMap::new(),
        }
    }
}

pub fn expand_env_vars(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if i + 2 < bytes.len() && bytes[i] == b'$' && bytes[i + 1] == b'{' {
            if let Some(rel_end) = input[i + 2..].find('}') {
                let var = &input[i + 2..i + 2 + rel_end];
                if !var.is_empty() && var.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                    if let Ok(val) = env::var(var) {
                        out.push_str(&val);
                    }
                    i += 3 + rel_end;
                    continue;
                }
            }
        }
        if let Some(ch) = input[i..].chars().next() {
            out.push(ch);
            i += ch.len_utf8();
        } else {
            break;
        }
    }
    out
}

fn strip_comment(raw: &str) -> &str {
    let mut in_single = false;
    let mut in_double = false;
    for (idx, ch) in raw.char_indices() {
        match ch {
            '\'' if !in_double => in_single = !in_single,
            '"' if !in_single => in_double = !in_double,
            '#' if !in_single && !in_double => {
                if idx == 0 || raw[..idx].ends_with(|c: char| c.is_whitespace()) {
                    return raw[..idx].trim_end();
                }
            }
            _ => {}
        }
    }
    raw.trim_end()
}

fn unquote(raw: &str) -> String {
    let t = raw.trim();
    if t.len() >= 2
        && ((t.starts_with('"') && t.ends_with('"')) || (t.starts_with('\'') && t.ends_with('\'')))
    {
        expand_env_vars(&t[1..t.len() - 1])
    } else {
        expand_env_vars(t)
    }
}

fn parse_bool(raw: &str) -> Option<bool> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "true" | "yes" | "on" | "1" => Some(true),
        "false" | "no" | "off" | "0" => Some(false),
        _ => None,
    }
}

fn sanitize_label(raw: &str) -> String {
    raw.chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        .take(48)
        .collect()
}

pub fn parse_yaml_config(yaml: &str, cfg: &mut AppConfig) {
    let mut section = String::new();
    for raw_line in yaml.lines() {
        let cleaned = strip_comment(raw_line);
        let trimmed = cleaned.trim();
        if trimmed.is_empty() {
            continue;
        }
        let indent = cleaned.chars().take_while(|c| *c == ' ').count();
        let Some((k_raw, v_raw)) = trimmed.split_once(':') else {
            continue;
        };
        let key = unquote(k_raw).trim().to_string();
        let val_raw = v_raw.trim();

        if indent == 0 {
            if val_raw.is_empty() {
                section = key.to_ascii_lowercase();
            } else {
                section.clear();
                let v = unquote(val_raw);
                if key == "auto_discover_prefix" {
                    cfg.auto_discover_prefix = if v.is_empty() || v == "null" {
                        None
                    } else {
                        Some(v)
                    };
                }
            }
            continue;
        }

        if section == "controllers" {
            let label = sanitize_label(&unquote(val_raw));
            if let Ok(ip) = key.parse::<IpAddr>() {
                if !label.is_empty() {
                    cfg.controllers.insert(ip, label);
                }
            }
            continue;
        }

        let v = unquote(val_raw);
        let opt_val = if v.is_empty() || v == "null" || v == "~" {
            None
        } else {
            Some(v.clone())
        };

        match (section.as_str(), key.as_str()) {
            ("capture", "interface") => {
                if let Some(iface) = opt_val {
                    cfg.interface = iface;
                }
            }
            ("capture", "matter_port") => {
                if let Ok(p) = v.parse::<u16>() {
                    if p > 0 {
                        cfg.matter_port = p;
                    }
                }
            }
            ("capture", "mdns_port") => {
                if let Ok(p) = v.parse::<u16>() {
                    if p > 0 {
                        cfg.mdns_port = p;
                    }
                }
            }
            ("capture", "drop_privileges_after_bpf") => {
                if let Some(b) = parse_bool(&v) {
                    cfg.drop_privileges_after_bpf = b;
                }
            }
            ("bridge", "ip") => {
                if let Ok(ip) = v.parse::<IpAddr>() {
                    cfg.bridge_ip = ip;
                }
            }
            ("bridge", "health_url") => cfg.bridge_health_url = opt_val,
            ("bridge", "ack_timeout_ms") => {
                if let Ok(ms) = v.parse::<u64>() {
                    cfg.ack_timeout_ms = ms.clamp(250, 30_000);
                }
            }
            ("bridge", "standalone_ack_filter") => {
                if let Some(b) = parse_bool(&v) {
                    cfg.standalone_ack_filter = b;
                }
            }
            ("server", "bind") => {
                if let Some(b) = opt_val {
                    cfg.bind_addr = b;
                }
            }
            ("server", "enable_ui") => {
                if let Some(b) = parse_bool(&v) {
                    cfg.enable_ui = b;
                }
            }
            _ => {}
        }
    }
}

impl AppConfig {
    pub fn load() -> Self {
        let args: Vec<String> = env::args().collect();
        let mut cfg = AppConfig::default();

        let mut yaml_path = env::var("MATTER_EXPORTER_CONFIG")
            .ok()
            .filter(|s| !s.trim().is_empty());

        let mut i = 1;
        while i < args.len() {
            if args[i] == "--config" && i + 1 < args.len() {
                yaml_path = Some(args[i + 1].clone());
                i += 1;
            }
            i += 1;
        }

        if yaml_path.is_none() {
            for cand in ["./config.yaml", "/config/config.yaml"] {
                if Path::new(cand).is_file() {
                    yaml_path = Some(cand.to_string());
                    break;
                }
            }
        }

        if let Some(path) = &yaml_path {
            match fs::read_to_string(path) {
                Ok(raw) => {
                    parse_yaml_config(&raw, &mut cfg);
                    cfg.config_path = Some(path.clone());
                }
                Err(e) => {
                    eprintln!("[matter-echo-delta] WARN: failed to read config '{path}': {e}");
                }
            }
        }

        // Environment variable overrides
        if let Ok(v) = env::var("MATTER_DEMO") {
            if let Some(b) = parse_bool(&v) {
                cfg.demo_mode = b;
            }
        }
        if let Ok(v) = env::var("MATTER_SNIFF_IFACE") {
            if !v.trim().is_empty() {
                cfg.interface = v.trim().to_string();
            }
        }
        if let Ok(v) = env::var("MATTER_BRIDGE_IP") {
            if let Ok(ip) = v.trim().parse::<IpAddr>() {
                cfg.bridge_ip = ip;
            }
        }
        if let Ok(v) = env::var("MATTER_BRIDGE_HEALTH_URL") {
            let trimmed = v.trim();
            cfg.bridge_health_url = if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            };
        }
        if let Ok(v) = env::var("MATTER_UDP_PORT") {
            if let Ok(p) = v.trim().parse::<u16>() {
                if p > 0 {
                    cfg.matter_port = p;
                }
            }
        }
        if let Ok(v) = env::var("MATTER_MDNS_PORT") {
            if let Ok(p) = v.trim().parse::<u16>() {
                if p > 0 {
                    cfg.mdns_port = p;
                }
            }
        }
        if let Ok(v) = env::var("MATTER_ACK_TIMEOUT_MS") {
            if let Ok(ms) = v.trim().parse::<u64>() {
                cfg.ack_timeout_ms = ms.clamp(250, 30_000);
            }
        }
        if let Ok(v) = env::var("MATTER_BIND") {
            if !v.trim().is_empty() {
                cfg.bind_addr = v.trim().to_string();
            }
        }
        if let Ok(v) = env::var("MATTER_AUTO_DISCOVER_PREFIX") {
            let trimmed = v.trim();
            cfg.auto_discover_prefix = if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            };
        }
        if let Ok(v) = env::var("MATTER_CONTROLLERS") {
            // Optional compact format: "192.0.2.10=echo-living,192.0.2.11=echo-kitchen"
            for pair in v.split(',') {
                if let Some((ip_s, name_s)) = pair.split_once('=') {
                    if let Ok(ip) = ip_s.trim().parse::<IpAddr>() {
                        let lbl = sanitize_label(name_s.trim());
                        if !lbl.is_empty() {
                            cfg.controllers.insert(ip, lbl);
                        }
                    }
                }
            }
        }

        // CLI flag overrides
        let mut idx = 1;
        while idx < args.len() {
            match args[idx].as_str() {
                "--demo" => cfg.demo_mode = true,
                "--once" => {
                    cfg.demo_mode = true;
                    cfg.dump_once = true;
                }
                "--no-ui" => cfg.enable_ui = false,
                "--bind" if idx + 1 < args.len() => {
                    cfg.bind_addr = args[idx + 1].clone();
                    idx += 1;
                }
                "--iface" if idx + 1 < args.len() => {
                    cfg.interface = args[idx + 1].clone();
                    idx += 1;
                }
                "--bridge-ip" if idx + 1 < args.len() => {
                    if let Ok(ip) = args[idx + 1].parse::<IpAddr>() {
                        cfg.bridge_ip = ip;
                    }
                    idx += 1;
                }
                "--help" | "-h" => {
                    println!(
                        "matter-echo-delta-exporter v{} — Passive Matter UDP/5540 & mDNS UDP/5353 BPF Exporter\n\
                         Usage: matter-echo-delta-exporter [--config config.yaml] [--demo] [--once] [--bind 127.0.0.1:9124] [--iface eth0] [--bridge-ip IP]\n\
                         Endpoints: GET / (Status UI), GET /metrics (Prometheus), GET /api/status (JSON), GET /healthz",
                        env!("CARGO_PKG_VERSION")
                    );
                    std::process::exit(0);
                }
                _ => {}
            }
            idx += 1;
        }

        cfg
    }

    pub fn to_correlator_config(&self) -> CorrelatorConfig {
        let mut cc = CorrelatorConfig::new(self.bridge_ip, self.ack_timeout_ms);
        cc.matter_port = self.matter_port;
        cc.mdns_port = self.mdns_port;
        cc.standalone_ack_filter = self.standalone_ack_filter;
        cc.auto_discover_prefix = self.auto_discover_prefix.clone();
        cc.controllers = self.controllers.clone();
        cc
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_yaml_config_and_sanitizes_labels() {
        let mut cfg = AppConfig::default();
        let yaml = r#"
capture:
  interface: "enp2s0"
  matter_port: 5540
  mdns_port: 5353
  drop_privileges_after_bpf: true

bridge:
  ip: "198.51.100.20"
  health_url: "http://127.0.0.1:8482/"
  ack_timeout_ms: 2000
  standalone_ack_filter: true

server:
  bind: "127.0.0.1:9124"
  enable_ui: true

auto_discover_prefix: "192.0.2."
controllers:
  "192.0.2.10": "echo-living"
  "192.0.2.11": "echo-kitchen;DROP"
"#;
        parse_yaml_config(yaml, &mut cfg);
        assert_eq!(cfg.interface, "enp2s0");
        assert_eq!(cfg.bridge_ip, IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)));
        assert_eq!(cfg.ack_timeout_ms, 2000);
        assert_eq!(cfg.auto_discover_prefix.as_deref(), Some("192.0.2."));
        assert_eq!(
            cfg.controllers
                .get(&IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)))
                .map(String::as_str),
            Some("echo-living")
        );
        // Semicolon stripped from Prometheus label value
        assert_eq!(
            cfg.controllers
                .get(&IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11)))
                .map(String::as_str),
            Some("echo-kitchenDROP")
        );
    }
}
