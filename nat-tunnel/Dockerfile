# Dockerfile

# Build stage
FROM rust:1.75-slim AS build

# Install dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy Cargo.toml and Cargo.lock
COPY Cargo.toml Cargo.lock ./

# Build dependencies
RUN cargo build --release

# Copy source code
COPY src ./src
COPY tests ./tests

# Run integration tests
RUN cargo test -- --test harness

# Final stage
FROM debian:12-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy built binary
COPY --from=build /app/target/release/nat-tunnel .

# Expose port
EXPOSE 8080

# Run the binary
ENTRYPOINT ["/app/nat-tunnel"]
CMD ["--help"]
