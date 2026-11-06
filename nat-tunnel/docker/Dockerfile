
# Build stage
FROM rust:1-bookworm AS builder

WORKDIR /app

COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN cargo build --release --no-default-features

# Runtime stage
FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        iproute2 \
        iptables \
        iputils-ping \
        netcat-openbsd \
        procps \
        python3 \
        tcpdump \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/nat-tunnel /usr/local/bin/nat-tunnel

COPY docker/router-entrypoint.sh \
     docker/internet-entrypoint.sh \
     docker/peer-entrypoint-a.sh \
     docker/peer-entrypoint-b.sh \
     /usr/local/bin/

RUN chmod 0755 \
    /usr/local/bin/nat-tunnel \
    /usr/local/bin/router-entrypoint.sh \
    /usr/local/bin/internet-entrypoint.sh \
    /usr/local/bin/peer-entrypoint-a.sh \
    /usr/local/bin/peer-entrypoint-b.sh

ENTRYPOINT ["nat-tunnel"]
CMD ["--help"]
