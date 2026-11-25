# Security Policy

## Threat Model & Hardening Controls

- **Zero payload decryption:** `matter-echo-delta-exporter` never reads, stores, or requests Matter CASE fabric keys. Only Ethernet/IP/UDP header metadata and `_matter` mDNS query/response flags are inspected.
- **In-kernel classic BPF filtering:** A 25-instruction `SO_ATTACH_FILTER` program drops non-Matter/non-mDNS packets inside the Linux kernel and caps frame reads to 512 bytes.
- **Immediate post-attach capability drop:** In live capture mode, `CAP_NET_RAW` is used solely to open and bind the read-only `AF_PACKET` socket, then cleared (`CapEff = 0`) via Linux `capset` before entering the capture loop.
- **Strict container isolation:** `read_only: true`, `cap_drop: [ALL]`, `no-new-privileges:true`, `mem_limit: 32m`, `cpus: 0.25`, `pids_limit: 32`, zero `docker.sock`.
- **Read-only HTTP server:** Accepts only `GET` and `HEAD`, binds to `127.0.0.1:9124` by default, serves 0 external CDNs, and enforces `CSP`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, and `Cache-Control: no-store`.
- **Zero third-party Rust crates:** Built exclusively on Rust `std`, eliminating transitive supply-chain dependencies.

## Reporting a Vulnerability

Open a private security advisory on GitHub or report via [blog.ravindra-job.fr](https://blog.ravindra-job.fr). Do not disclose live network details publicly before a fix is published.
