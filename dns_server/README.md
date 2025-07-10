# DNS Server with Multi-Architecture Support

Full-featured DNS server with primary/secondary architecture, zone transfers (AXFR/IXFR), TSIG authentication, load balancing gateway, and DoS protection.

## Features
- **Multi-Server**: Primary/Secondary with auto-sync | **Gateway**: Load balancing + health checks
- **Security**: TSIG authentication, ACLs, rate limiting | **Protocols**: UDP/TCP/DoT/DoH  
- **Zone Management**: AXFR/IXFR transfers, dynamic updates | **Forwarding**: Upstream DNS support

## Quick Start

```bash
# 1. Setup
python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt
bash generate_tsig_key.sh && bash generate_certs.sh

# 2. Run automated tests
./test_multi_server_architecture.sh  # Full architecture test
./test_dns_gateway.sh                # Gateway + load balancing test

# 3. Interactive demo
python dns_architecture_manager.py --mode demo
```

## Server Configurations & Workflows

### 1. Basic DNS Server (Development)
```bash
python -m dns_server.main --zone dns_server/zones/primary.zone --port-udp 5353 --port-tcp 5354
# Test: dig @127.0.0.1 -p 5353 www.example.com A
```

### 2. DNS Server with Upstream Forwarding (Hybrid Mode)
```bash
# Answers local zones + forwards external queries to Google DNS
python -m dns_server.main --zone dns_server/zones/primary.zone --port-udp 5353   --port-tcp 5354  --forwarder 8.8.8.8

# Test local zone:     dig @127.0.0.1 -p 5353 www.example.com A
# Test forwarding:     dig @127.0.0.1 -p 5353 www.google.com A
# Test NXDOMAIN:       dig @127.0.0.1 -p 5353 nonexistent.invalid A
```

### 3. TSIG-Secured Server (Production)
```bash
python -m dns_server.main --zone dns_server/zones/primary.zone --port-udp 5353 --port-tcp 5354\
  --tsig-name tsig-key-1752130646 --tsig-secret 2vgKc8+OH9UMBrRYTBYOmjffLACFVtGQPgXjt6fw05k=

# Test authenticated:   dig @127.0.0.1 -p 5353 www.example.com A -y tsig-key-1752130646:2vgKc8+...
# Test unauthenticated: dig @127.0.0.1 -p 5353 www.example.com A  # Will timeout
```

### 4. Primary-Secondary Setup
```bash
# Terminal 1: Primary server
python -m dns_server.main --zone dns_server/zones/primary.zone --port-udp 5353 --port-tcp 5354 \
  --tsig-name tsig-key-1752130646 --tsig-secret 2vgKc8+... \
  --forwarder 8.8.8.8  #if You want it as a local DNS server.If You want it as an ANS,don't forward

# Terminal 2: Secondary server (authoritative only)
python -m dns_server.main --port-udp 7353 --port-tcp 7354 --secondary \
  --primary-server 127.0.0.1 --primary-port 5354 \
  --tsig-name tsig-key-1752130646 --tsig-secret 2vgKc8+...

# Terminal 3: Secondary server with forwarding (hybrid)  
python -m dns_server.main --port-udp 8353 --port-tcp 8354 --secondary \
  --primary-server 127.0.0.1 --primary-port 5354 --forwarder 8.8.8.8 \
  --tsig-name tsig-key-1752130646 --tsig-secret 2vgKc8+...

# Test zone transfer: dig @127.0.0.1 -p 5353 example.com AXFR +tcp
# Test secondary:     dig @127.0.0.1 -p 7353 www.example.com A
# Test hybrid:        dig @127.0.0.1 -p 8353 www.google.com A  # Should forward
```

### 5. Load Balancing Gateway
```bash
# Start backend servers first (see above), then:
python -m dns_server.utils.dns_gateway --listen-port 9353 \
  --backend-servers "127.0.0.1:5353" "127.0.0.1:7353" "127.0.0.1:8353" \
  --tsig-key-name tsig-key-1752130646 --tsig-secret 2vgKc8+...

# Test load balancing: for i in {1..5}; do dig @127.0.0.1 -p 9353 www.example.com A +short; done
```

### 6. ACL & Rate Limiting (DoS Protection)
```bash
# Rate limiting
python -m dns_server.main --zone dns_server/zones/primary.zone --port-udp 5353 \
  --rate-limit-threshold 10 --rate-limit-window 5 --rate-limit-ban-duration 300

# Network ACL
python -m dns_server.main --zone dns_server/zones/primary.zone --port-udp 5353 \
  --allow 192.168.1.0/24 --deny 10.0.0.0/8

# Test rate limiting: for i in {1..15}; do dig @127.0.0.1 -p 5353 test$i.example.com A; done
```

### 7. Full-Featured Server (DoT + DoH)
```bash
python -m dns_server.main --zone dns_server/zones/primary.zone \
  --certfile dns_server/certs/cert.pem --certkey dns_server/certs/key.pem \
  --tsig-name tsig-key-1752130646 --tsig-secret 2vgKc8+... \
  --port-udp 53 --port-tcp 53 --port-dot 853 --port-doh 443

# Test DoT: dig @127.0.0.1 -p 853 www.example.com A +tls
```

## Testing Workflows

### Basic Testing
```bash
# A record:        dig @127.0.0.1 -p 5353 www.example.com A
# MX record:       dig @127.0.0.1 -p 5353 example.com MX  
# Zone transfer:   dig @127.0.0.1 -p 5353 example.com AXFR +tcp
# Cache test:      dig @127.0.0.1 -p 5353 www.example.com A  # Run twice
```

### TSIG Authentication Testing
```bash
# Without TSIG (will timeout):
dig @127.0.0.1 -p 5353 www.example.com A

# With TSIG (will work):
dig @127.0.0.1 -p 5353 www.example.com A -y tsig-key-1752130646:2vgKc8+OH9UMBrRYTBYOmjffLaCFVtGQPgXjt6fw05k=
```

### Dynamic Updates Testing
```bash
# Using nsupdate:
nsupdate << EOF
server 127.0.0.1 5353
key hmac-sha256:tsig-key-1752130646 2vgKc8+OH9UMBrRYTBYOmjffLaCFVtGQPgXjt6fw05k=
zone example.com
update add test.example.com 300 A 1.2.3.4
send
quit
EOF

# Verify: dig @127.0.0.1 -p 5353 test.example.com A
```

### Rate Limiting & DoS Testing
```bash
# Test burst attack (should trigger blocking):
for i in {1..20}; do dig @127.0.0.1 -p 5353 test$i.example.com A +short; done

# Test sustained attack:
python test_rate_limiting.py --server 127.0.0.1 --port 5353 --test sustained
```

### Gateway Load Balancing Testing
```bash
# Test round-robin distribution:
for i in {1..10}; do 
  echo "Query $i:"; 
  dig @127.0.0.1 -p 9353 www.example.com A +short; 
  sleep 0.5; 
done
```

## Architecture Modes

| Mode | Use Case | Command Pattern |
|------|----------|-----------------|
| **Basic** | Development | `--zone file --port-udp 5353` |
| **Hybrid** | Mixed auth + recursive | `+ --forwarder 8.8.8.8` |
| **Secured** | Production | `+ --tsig-name key --tsig-secret secret` |
| **Primary/Secondary** | High availability | `--secondary --primary-server IP` |
| **Gateway** | Load balancing | `dns_gateway --backend-servers` |

## Key Command Line Options

| Flag | Purpose | Example |
|------|---------|---------|
| `--zone` | Zone file | `dns_server/zones/primary.zone` |
| `--forwarder` | Upstream DNS | `8.8.8.8` (Google), `1.1.1.1` (Cloudflare) |
| `--tsig-name/secret` | Authentication | `tsig-key-1752130646` |
| `--allow/deny` | Network ACL | `192.168.1.0/24` |
| `--rate-limit-*` | DoS protection | `--rate-limit-threshold 50` |
| `--secondary` | Secondary mode | `--primary-server 127.0.0.1` |
| `--certfile/certkey` | TLS/HTTPS | `cert.pem`, `key.pem` |

## Common Issues & Solutions

### TSIG Errors
**Error**: `got signed message without keyring`  
**Cause**: Gateway sends TSIG-signed queries but backend server has no TSIG key  
**Fix**: Add TSIG to backend server: `--tsig-name key --tsig-secret secret`

### NXDOMAIN Crashes
**Error**: `dns.resolver.NXDOMAIN: The DNS query name does not exist`  
**Cause**: Earlier versions crashed on upstream NXDOMAIN responses  
**Fix**: Now handled automatically - server continues running

### Secondary vs Forwarder Confusion
**Question**: "Why doesn't my secondary server forward to primary?"  
**Answer**: Secondary servers sync zone data via AXFR/IXFR, they don't forward queries. To enable forwarding from secondary, add `--forwarder 8.8.8.8`

```bash
# Secondary (authoritative only):      --secondary --primary-server IP  
# Secondary with forwarding (hybrid):  --secondary --primary-server IP --forwarder 8.8.8.8
```

### Port Conflicts  
**Error**: `Address already in use`  
**Fix**: Use different ports: `--port-udp 5353 --port-tcp 5354`

## Key Files & Directories
```
dns_server/
├── main.py              # Server entry point
├── handler.py           # DNS query processing
├── utils/
│   ├── dns_gateway.py   # Load balancing gateway
│   ├── tsig.py         # TSIG authentication  
│   ├── acl.py          # Access control
│   └── cache.py        # DNS caching
├── zones/
│   ├── primary.zone    # Primary zone data
│   ├── secondary1.zone # Secondary zone files
│   └── secondary2.zone
├── certs/              # TLS certificates (generated)
└── keys/               # TSIG keys (generated)

test_*.sh               # Automated test scripts
*_manager.py           # Interactive management tools
```
