"""Safeguard & contract tests for the open-source Rust matter-echo-delta-exporter."""
from pathlib import Path
import json
import re
import yaml

MODULE_DIR = Path(__file__).resolve().parent.parent


def test_zero_external_crates_and_repo_structure():
    cargo = (MODULE_DIR / "Cargo.toml").read_text(encoding="utf-8")
    assert 'name = "matter-echo-delta-exporter"' in cargo
    assert 'repository = "https://github.com/ravindrajob/matter-echo-delta-exporter"' in cargo
    deps_block = cargo.split("[dependencies]")[1].split("[profile.")[0]
    active_deps = [
        line.strip()
        for line in deps_block.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    assert active_deps == [], f"Unexpected external crates in Cargo.toml: {active_deps}"

    for rel in (
        "src/lib.rs",
        "src/main.rs",
        "src/config.rs",
        "src/linux_capture.rs",
        "src/ui/index.html",
        "config.yaml.example",
        "Dockerfile",
        "docker-compose.yml",
        "LICENSE",
        "SECURITY.md",
        "monitoring/grafana-dashboard.json",
        "monitoring/prometheus-alerts.yml",
    ):
        assert (MODULE_DIR / rel).is_file(), f"Missing required file: {rel}"


def test_config_yaml_and_monitoring_artifacts_valid():
    cfg = yaml.safe_load((MODULE_DIR / "config.yaml.example").read_text(encoding="utf-8"))
    assert cfg["capture"]["matter_port"] == 5540
    assert cfg["capture"]["mdns_port"] == 5353
    assert cfg["capture"]["drop_privileges_after_bpf"] is True
    assert cfg["bridge"]["standalone_ack_filter"] is True
    assert cfg["server"]["bind"].startswith("127.0.0.1:")

    dash = json.loads((MODULE_DIR / "monitoring/grafana-dashboard.json").read_text(encoding="utf-8"))
    assert dash["uid"] == "matter-echo-delta-l4"
    assert len(dash["panels"]) >= 6
    for panel in dash["panels"]:
        if panel["type"] == "stat":
            assert all(t.get("instant") is True for t in panel["targets"])

    alerts = yaml.safe_load((MODULE_DIR / "monitoring/prometheus-alerts.yml").read_text(encoding="utf-8"))
    names = {r["alert"] for g in alerts["groups"] for r in g["rules"]}
    assert "MatterUnansweredMrpBurst" in names
    assert "MatterBridgeSilentDisconnect" in names


def test_hardening_and_zero_cdn_invariants():
    compose = (MODULE_DIR / "docker-compose.yml").read_text(encoding="utf-8")
    linux_rs = (MODULE_DIR / "src/linux_capture.rs").read_text(encoding="utf-8")
    main_rs = (MODULE_DIR / "src/main.rs").read_text(encoding="utf-8")
    lib_rs = (MODULE_DIR / "src/lib.rs").read_text(encoding="utf-8")
    ui_html = (MODULE_DIR / "src/ui/index.html").read_text(encoding="utf-8")

    assert "read_only: true" in compose
    assert "no-new-privileges:true" in compose
    assert "cap_drop:" in compose
    assert "NET_RAW" in compose
    assert "mem_limit: 32m" in compose
    assert "pids_limit: 32" in compose
    assert "docker.sock" not in compose

    assert "SO_ATTACH_FILTER" in linux_rs
    assert "drop_all_linux_capabilities" in linux_rs
    assert "standalone_acks_total" in lib_rs
    assert "X-Frame-Options: DENY" in main_rs
    assert "Content-Security-Policy:" in main_rs
    assert not re.search(r"https?://(?:cdn\.|unpkg\.|cdnjs\.|fonts\.googleapis)", ui_html)
