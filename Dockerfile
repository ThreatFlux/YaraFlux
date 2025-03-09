# Stage 0: Python base image
FROM python:3.13-slim AS base

# Build arguments
ARG USER=yaraflux
ARG UID=10001

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libc6-dev \
    python3-dev \
    libssl-dev \
    yara \
    libmagic-dev \
    libjansson-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -g ${UID} ${USER} && \
    useradd -u ${UID} -g ${USER} -s /bin/bash -m ${USER} && \
    mkdir -p /app /app/data/rules/community /app/data/rules/custom /app/data/samples /app/data/results && \
    chown -R ${USER}:${USER} /app

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app \
    DEBUG=true

# Stage 1: Builder stage
FROM base AS builder

# Set working directory
WORKDIR /app

# Copy requirements file
COPY requirements.txt /app/

# Install dependencies
RUN pip install --no-cache-dir -U pip setuptools wheel && \
    pip install --no-cache-dir -r requirements.txt

# Stage 2: Production stage
FROM base AS production

# Build arguments for metadata
ARG BUILD_DATE
ARG VERSION=1.0.0

# Add metadata
LABEL org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.authors="wyatt@threatflux.ai" \
      org.opencontainers.image.url="https://github.com/ThreatFlux/YaraFlux" \
      org.opencontainers.image.documentation="https://github.com/ThreatFlux/YaraFlux" \
      org.opencontainers.image.source="https://github.com/ThreatFlux/YaraFlux" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.vendor="ThreatFlux" \
      org.opencontainers.image.title="yaraflux-mcp-server" \
      org.opencontainers.image.description="YaraFlux MCP Server for Claude Desktop integration"

# Set working directory
WORKDIR /app

# Copy dependencies from builder
COPY --from=builder /usr/local/lib/python3.13/site-packages /usr/local/lib/python3.13/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application code
COPY --chown=${USER}:${USER} src/yaraflux_mcp_server /app/yaraflux_mcp_server

# Copy entrypoint script
COPY entrypoint.sh /app/
RUN chmod +x /app/entrypoint.sh

# Switch to non-root user
USER ${USER}

# Health check
HEALTHCHECK --interval=5m --timeout=3s \
    CMD python -c "import yaraflux_mcp_server; print('healthy')" || exit 1

# Run the server
ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["--transport", "stdio"]
