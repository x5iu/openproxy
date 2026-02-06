FROM ubuntu:22.04

ARG TARGETARCH

COPY openproxy-linux-${TARGETARCH} /usr/local/bin/openproxy

# Note: Port is determined by config file (https_port/http_port)
# Map ports at runtime: docker run -p <host_port>:<container_port>

# Run the application
ENTRYPOINT ["/usr/local/bin/openproxy"]
CMD ["start", "-c", "/config.yml", "--enable-health-check"]
