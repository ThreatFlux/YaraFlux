FROM python:3.13-slim

LABEL maintainer="ThreatFlux <info@threatflux.com>"
LABEL description="YaraFlux MCP Server for Claude Desktop integration"
LABEL version="0.1.0"

# Install system dependencies and YARA
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    python3-dev \
    libssl-dev \
    yara \
    libmagic-dev \
    libjansson-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Set up working directory
WORKDIR /app

# Copy the source code
COPY src/yaraflux_mcp_server /app/yaraflux_mcp_server

# Install Python dependencies first
COPY requirements.txt /app/
RUN pip install --no-cache-dir -U pip setuptools wheel \
    && pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir "mcp[cli]>=1.3.0"

# Create required directories
RUN mkdir -p /app/data/rules/community /app/data/rules/custom /app/data/samples /app/data/results

# Set environment variables
ENV PYTHONPATH=/app \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DEBUG=true

# Create and setup entrypoint script
COPY entrypoint.sh /app/
RUN chmod +x /app/entrypoint.sh

# Run the server with stdio transport
ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["--transport", "stdio"]
