# Multi-stage zero-dependency Rust musl build (< 1 MB static binary)
FROM rust:1.83-alpine AS builder
WORKDIR /src
COPY Cargo.toml ./
COPY src ./src
RUN cargo test --release && cargo build --release

FROM alpine:3.21
RUN adduser -D -u 1000 exporter
WORKDIR /app
COPY --from=builder /src/target/release/matter-echo-delta-exporter /usr/local/bin/matter-echo-delta-exporter
EXPOSE 9124
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD wget -qO- http://127.0.0.1:9124/healthz >/dev/null 2>&1 || exit 1
# Live AF_PACKET capture needs CAP_NET_RAW only at startup (dropped right after SO_ATTACH_FILTER).
# For --demo mode, run with `--user 1000:1000 --cap-drop ALL`.
ENTRYPOINT ["/usr/local/bin/matter-echo-delta-exporter"]
