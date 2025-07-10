# DNS Server with Multi-Architecture Support

A comprehensive DNS server implementation supporting primary/secondary architecture, zone transfers (AXFR/IXFR), DNS updates, TSIG authentication, and multiple protocols (UDP/TCP/DoT/DoH).

## ✅ Features Implemented

- **Multi-Server Architecture**: Primary/Secondary with automatic synchronization
- **Zone Transfers**: AXFR (full) and IXFR (incremental) zone transfers
- **DNS Updates**: Dynamic updates with TSIG authentication and forwarding
- **Multiple Protocols**: UDP, TCP, DNS-over-TLS (DoT), DNS-over-HTTPS (DoH)
- **Security**: TSIG authentication, ACLs, secure zone transfers
- **Rate Limiting & DOS Protection**: Configurable rate limiting with IP banning
- **Record Types**: A, MX, SOA, NS, CNAME, TXT records
- **Caching**: DNS response caching with TTL management

## 🚀 Quick Start

### Complete Architecture Test
```bash
# Run comprehensive test demonstrating full architecture
./test_multi_server_architecture.sh
```

### Manual Setup
```bash
# 1. Setup environment
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# 2. Generate keys and certificates
bash generate_tsig_key.sh    # For TSIG authentication
bash generate_certs.sh       # For DoT/DoH

# 3. Start primary server
python -m dns_server.main --port-udp 5353 --port-tcp 5354

# 4. Start secondary servers (in separate terminals)
python -m dns_server.main --port-udp 7353 --port-tcp 7354 --secondary --primary-server 127.0.0.1 --primary-port 5354
python -m dns_server.main --port-udp 8353 --port-tcp 8354 --secondary --primary-server 127.0.0.1 --primary-port 5354
```

## Server Configurations

### Basic DNS Server
```bash
python -m dns_server.main \
  --zone dns_server/zones/primary.zone \
  --addr 0.0.0.0 \
  --port-udp 53 \
  --port-tcp 53
```

### TSIG-Secured Server (All queries require authentication)
```bash
python -m dns_server.main \
  --zone dns_server/zones/primary.zone \
  --tsig-name tsig-key-1752130646 \
  --tsig-secret dGVzdGtleXNlY3JldDEyMzQ1Njc4OTBhYmNkZWZnaGlqaw== \
  --addr 127.0.0.1 \
  --port-udp 5353 \
  --port-tcp 5354
```

### ACL-Protected Server
```bash
python -m dns_server.main \
  --zone dns_server/zones/primary.zone \
  --allow 192.168.1.0/24 \
  --deny 10.0.0.0/8 \
  --addr 0.0.0.0 \
  --port-udp 5353 \
  --port-tcp 5354
```

### Full-Featured Server (DoT + DoH + TSIG + ACL)
```bash
python -m dns_server.main \
  --zone dns_server/zones/primary.zone \
  --certfile dns_server/certs/cert.pem \
  --certkey dns_server/certs/key.pem \
  --tsig-name tsig-key-1752130646 \
  --tsig-secret dGVzdGtleXNlY3JldDEyMzQ1Njc4OTBhYmNkZWZnaGlqaw== \
  --allow 192.168.0.0/16 \
  --addr 0.0.0.0 \
  --port-udp 53 \
  --port-tcp 53 \
  --port-dot 853 \
  --port-doh 443
```

### Primary-Secondary Setup

**Primary Server:**
```bash
python -m dns_server.main \
  --zone dns_server/zones/primary.zone \
  --tsig-name tsig-key-1752130646 \
  --tsig-secret dGVzdGtleXNlY3JldDEyMzQ1Njc4OTBhYmNkZWZnaGlqaw== \
  --addr 0.0.0.0 \
  --port-udp 5353 \
  --port-tcp 5354
```

**Secondary Server:**
```bash
python -m dns_server.main \
  --zone dns_server/zones/secondary1.zone \
  --secondary \
  --primary-server 127.0.0.1 \
  --primary-port 5354 \
  --refresh-interval 300 \
  --tsig-name tsig-key-1752130646 \
  --tsig-secret dGVzdGtleXNlY3JldDEyMzQ1Njc4OTBhYmNkZWZnaGlqaw== \
  --addr 0.0.0.0 \
  --port-udp 7353 \
  --port-tcp 7354
```

### Rate Limited Server (DOS Protection)
```bash
python -m dns_server.main \
  --zone dns_server/zones/primary.zone \
  --rate-limit-threshold 50 \
  --rate-limit-window 10 \
  --rate-limit-ban-duration 600 \
  --addr 0.0.0.0 \
  --port-udp 5353 \
  --port-tcp 5354
```

### Forwarder Configuration
```bash
python -m dns_server.main \
  --zone dns_server/zones/primary.zone \
  --forwarder 8.8.8.8 \
  --addr 0.0.0.0 \
  --port-udp 5353 \
  --port-tcp 5354
```

## Testing Commands

### Basic Queries
```bash
# A record
dig @127.0.0.1 -p 5353 www.example.com A

# MX record  
dig @127.0.0.1 -p 5353 www.example.com MX

# Zone transfer (AXFR)
dig @127.0.0.1 -p 5353 example.com AXFR +tcp

# Cache test (run twice, second should be faster)
dig @127.0.0.1 -p 5353 www.example.com A
```

### TSIG Authentication
```bash
# Without TSIG (will timeout if TSIG required)
dig @127.0.0.1 -p 5353 example.com A

# With TSIG (using dig)
dig @127.0.0.1 -p 5353 example.com A -y tsig-key-1752130646:2vgKc8+OH9UMBrRYTBYOmjffLaCFVtGQPgXjt6fw05k=

# Python TSIG test
python test_tsig_authenticated.py
```

### DNS Updates
```bash
# Using nsupdate with TSIG
nsupdate << EOF
server 127.0.0.1 5353
key hmac-sha256:tsig-key-1752130646 2vgKc8+OH9UMBrRYTBYOmjffLaCFVtGQPgXjt6fw05k=
zone example.com
update add newtest.example.com 300 A 1.2.3.4
send
quit
EOF

# Using Python script
python test_update.py
```

### Rate Limiting & DOS Protection
```bash
# Test rate limiting features
python test_rate_limiting.py --server 127.0.0.1 --port 5353

# Test burst attack (should trigger blocking)
python test_rate_limiting.py --test burst

# Test sustained attack
python test_rate_limiting.py --test sustained
```

### ACL Testing
```bash
# Start server with ACL denying your IP
python -m dns_server.main --zone dns_server/zones/primary.zone --deny 127.0.0.0/24

# Test (should timeout)
dig @127.0.0.1 -p 5353 www.example.com A
```

## Command Line Options

| Option | Description | Example |
|--------|-------------|---------|
| `--zone` | Zone file path | `dns_server/zones/primary.zone` |
| `--addr` | Bind address | `0.0.0.0` or `127.0.0.1` |
| `--port-udp` | UDP port | `53` or `5353` |
| `--port-tcp` | TCP port | `53` or `5354` |
| `--port-dot` | DoT port | `853` |
| `--port-doh` | DoH port | `443` |
| `--certfile` | TLS certificate | `dns_server/certs/cert.pem` |
| `--certkey` | TLS private key | `dns_server/certs/key.pem` |
| `--tsig-name` | TSIG key name | `tsig-key-1752130646` |
| `--tsig-secret` | TSIG secret | `base64-encoded-secret` |
| `--allow` | Allow networks | `192.168.1.0/24` |
| `--deny` | Deny networks | `10.0.0.0/8` |
| `--forwarder` | Upstream DNS | `8.8.8.8` |
| `--secondary` | Run as secondary | Flag (no value) |
| `--primary-server` | Primary server IP | `127.0.0.1` |
| `--primary-port` | Primary server TCP port | `5354` |
| `--refresh-interval` | Zone refresh interval (seconds) | `300` |
| `--keyfile` | DNSSEC private key | `private.key` |
| `--rate-limit-threshold` | Max queries per IP in time window | `100` |
| `--rate-limit-window` | Rate limit time window (seconds) | `5` |
| `--rate-limit-ban-duration` | IP ban duration (seconds) | `300` |

## Features Status

| Feature | Status | Notes |
|---------|--------|-------|
| A/MX/SOA/NS Records | ✅ | Full support |
| AXFR/IXFR | ✅ | Zone transfers |
| DNS UPDATE | ✅ | Dynamic updates |
| Caching | ✅ | TTL-based |
| ACLs | ✅ | IP-based rules |
| TSIG | ✅ | HMAC-SHA256 |
| Rate Limiting | ✅ | DOS protection |
| DNSSEC | ⚠️ | Basic signing |
| DoT/DoH | ⚠️ | TLS support |

✅ = Production ready  
⚠️ = Functional, needs testing

## Development

### Key Files
- `dns_server/main.py` - Server entry point
- `dns_server/handler.py` - DNS query handler  
- `dns_server/utils/tsig.py` - TSIG authentication
- `dns_server/utils/acl.py` - Access control
- `dns_server/zones/primary.zone` - Zone data

### Test Scripts
- `test_multi_server_architecture.sh` - Complete architecture test
- `test_rate_limiting.py` - Rate limiting and DOS protection tests
- `verify-deployment.sh` - Multi-VM deployment verification

### Security Notes
- TSIG keys should be generated per deployment
- Use ACLs to restrict zone transfers
- TLS certificates should be from trusted CA in production
- Store secrets in environment variables, not config files
