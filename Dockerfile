# Build stage
FROM rust:1.85-slim AS builder

WORKDIR /usr/src/app

# Copy Cargo files
COPY Cargo.toml ./

# Copy source code
COPY src ./src

# Build the application
RUN cargo build --release --bin openproxy

# Runtime stage
FROM ubuntu:22.04

# Copy the binary from builder stage
COPY --from=builder /usr/src/app/target/release/openproxy /usr/local/bin/openproxy

# Expose port
EXPOSE 443

# Run the application
ENTRYPOINT ["/usr/local/bin/openproxy"]
CMD ["start", "-c", "/config.yml", "--enable-health-check"]