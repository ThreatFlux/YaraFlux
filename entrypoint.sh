#!/bin/bash
set -e

echo "Starting YaraFlux MCP Server..."

# Create required directories
mkdir -p /app/data/rules/community /app/data/rules/custom /app/data/samples /app/data/results

# Run the MCP server directly
# The initialization will be handled by the server itself
cd /app && exec python -m yaraflux_mcp_server.mcp_server --transport stdio
