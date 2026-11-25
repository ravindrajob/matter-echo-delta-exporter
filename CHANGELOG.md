# Changelog

## v0.2.0 (2026-11-23)

- Standalone pure-Rust `std` release (`0` external crates, static musl binary `< 1 MB`).
- Live Linux `AF_PACKET` capture with 25-instruction classic kernel BPF filter (`IPv4`, `IPv6`, and `802.1Q` VLAN on `UDP/5540` and `UDP/5353`).
- Post-BPF Linux capability drop (`capset` clears `CapEff/CapPrm/CapInh` right after `SO_ATTACH_FILTER`).
- Matter Core Spec §4.11 Standalone ACK filter (`matter_echo_standalone_acks_total`) to eliminate false positives on unsolicited `ReportData` pushes.
- Zero-crate `config.yaml` loader (`defaults < config.yaml < ENV < CLI`), built-in read-only status UI (`GET /`), Prometheus `/metrics`, Grafana dashboard, and multi-arch CI/Release workflow.
