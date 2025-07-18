FROM python:3.12-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    dnsutils \
    redis-tools \
    bind9-utils \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the entire DNS server code
COPY . .

# Create necessary directories
RUN mkdir -p /app/dns_server/certs /app/dns_server/keys /app/logs

# Generate default certificates and keys
RUN bash generate_certs.sh && bash generate_tsig_key.sh

# Expose common DNS ports
EXPOSE 53/udp 53/tcp 853/tcp 443/tcp 5353/udp 5354/tcp

# Default entrypoint
ENTRYPOINT ["python", "-m", "dns_server.main"]
CMD ["--help"]
