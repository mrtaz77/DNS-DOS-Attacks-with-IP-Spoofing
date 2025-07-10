# DNS Server with Multi-Architecture Support

A comprehensive DNS server implementation supporting primary/secondary architecture, zone transfers (AXFR/IXFR), DNS updates, TSIG authentication, and multiple protocols (UDP/TCP/DoT/DoH).

## ✅ Features Implemented

- **Multi-Server Architecture**: Primary/Secondary with automatic synchronization
- **Zone Transfers**: AXFR (full) and IXFR (incremental) zone transfers
- **DNS Updates**: Dynamic updates with TSIG authentication and forwarding
- **Multiple Protocols**: UDP, TCP, DNS-over-TLS (DoT), DNS-over-HTTPS (DoH)
- **Security**: TSIG authentication, ACLs, secure zone transfers
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
python -m dns_server.main --port 5353 --tcp-port 5354

# 4. Start secondary servers (in separate terminals)
python -m dns_server.main --port 7353 --tcp-port 7354 --secondary --primary-host 127.0.0.1 --primary-port 5354
python -m dns_server.main --port 8353 --tcp-port 8354 --secondary --primary-host 127.0.0.1 --primary-port 5354
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
  --tsig-name <KEY_NAME> \
  --tsig-secret <SECRET> \
  --addr 127.0.0.1 \
  --port-udp 5353
```

### ACL-Protected Server
```bash
python -m dns_server.main \
  --zone dns_server/zones/primary.zone \
  --allow 192.168.1.0/24 \
  --deny 10.0.0.0/8 \
  --addr 0.0.0.0
```

### Full-Featured Server (DoT + DoH + TSIG + ACL)
```bash
python -m dns_server.main \
  --zone dns_server/zones/primary.zone \
  --certfile dns_server/certs/cert.pem \
  --certkey dns_server/certs/key.pem \
  --tsig-name <KEY_NAME> \
  --tsig-secret <SECRET> \
  --allow 192.168.0.0/16 \
  --addr 0.0.0.0
```

### Primary-Secondary Setup

**Primary (Master):**
```bash
python -m dns_server.main \
  --zone dns_server/zones/primary.zone \
  --tsig-name <KEY_NAME> \
  --tsig-secret <SECRET> \
  --addr 0.0.0.0 \
  --port-udp 53 \
  --port-tcp 53
```

**Secondary (Slave):**
```bash
python -m dns_server.main \
  --zone dns_server/zones/secondary.zone \
  --forwarder <PRIMARY_IP> \
  --tsig-name <KEY_NAME> \
  --tsig-secret <SECRET> \
  --addr 0.0.0.0 \
  --port-udp 5353
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
dig @127.0.0.1 -p 5353 example.com A -y <KEY_NAME>:<SECRET>

# Python TSIG test
python test_tsig_authenticated.py
```

### DNS Updates
```bash
# Using nsupdate with TSIG
nsupdate << EOF
server 127.0.0.1 5353
key hmac-sha256:<KEY_NAME> <SECRET>
zone example.com
update add testx.example.com 300 A 1.2.3.4
send
quit
EOF

# Using Python script
python test_update.py
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
| `--port-tcp` | TCP port | `53` or `5353` |
| `--port-tls` | DoT port | `853` |
| `--port-https` | DoH port | `443` |
| `--certfile` | TLS certificate | `dns_server/certs/cert.pem` |
| `--certkey` | TLS private key | `dns_server/certs/key.pem` |
| `--tsig-name` | TSIG key name | `tsig-key-123456` |
| `--tsig-secret` | TSIG secret | `base64-encoded-secret` |
| `--allow` | Allow networks | `192.168.1.0/24` |
| `--deny` | Deny networks | `10.0.0.0/8` |
| `--forwarder` | Upstream DNS | `8.8.8.8` |

## Features Status

| Feature | Status | Notes |
|---------|--------|-------|
| A/MX/SOA/NS Records | ✅ | Full support |
| AXFR/IXFR | ✅ | Zone transfers |
| DNS UPDATE | ✅ | Dynamic updates |
| Caching | ✅ | TTL-based |
| ACLs | ✅ | IP-based rules |
| TSIG | ✅ | HMAC-SHA256 |
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
- `test_tsig_authenticated.py` - TSIG validation tests
- `test_update.py` - DNS UPDATE tests  
- `test_axfr.py` - Zone transfer tests

### Security Notes
- TSIG keys should be generated per deployment
- Use ACLs to restrict zone transfers
- TLS certificates should be from trusted CA in production
- Store secrets in environment variables, not config files
