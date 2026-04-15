# Use Python 3.10-slim as base
FROM python:3.10-slim

# Set working directory
WORKDIR /app

# Install system dependencies (nmap if needed)
RUN apt-get update && apt-get install -y nmap && rm -rf /var/lib/apt/lists/*

# Copy scanner requirements and script
COPY scanner/ /app/scanner/
COPY reports/ /app/reports/

# Install python dependencies
RUN pip install --no-cache-dir requests scapy pyyaml prettytable

# Expose no ports as it's a CLI tool, but could expose if we served the reports
# For demo purposes, we just run the engine
ENTRYPOINT ["python", "scanner/engine.py"]
CMD ["127.0.0.1"]
