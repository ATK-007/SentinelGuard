# Use Python 3.10-slim as base
FROM python:3.10-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y nmap && rm -rf /var/lib/apt/lists/*

# Copy the entire project for installation
COPY . /app/

# Install the package and its dependencies
RUN pip install --no-cache-dir .

# SentinelGuard is now available as a CLI command
ENTRYPOINT ["sentinelguard"]
CMD ["127.0.0.1"]
