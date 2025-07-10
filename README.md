# DNS Server with Multi-Architecture Support

A comprehensive DNS server implementation supporting primary/secondary architecture, zone transfers (AXFR/IXFR), DNS updates, TSIG authentication, and multiple protocols (UDP/TCP/DoT/DoH).

## ✅ Features Implemented

- **Multi-Server Architecture**: Primary/Secondary with automatic synchronization
- **DNS Gateway & Load Balancing**: Enterprise-grade proxy with round-robin load balancing
- **Zone Transfers**: AXFR (full) and IXFR (incremental) zone transfers
- **DNS Updates**: Dynamic updates with TSIG authentication and forwarding
- **Multiple Protocols**: UDP, TCP, DNS-over-TLS (DoT), DNS-over-HTTPS (DoH)
- **Security**: TSIG authentication, ACLs, secure zone transfers
- **Rate Limiting & DOS Protection**: Configurable rate limiting with IP banning
- **Health Monitoring**: Automatic backend server health checks and failover
- **Record Types**: A, MX, SOA, NS, CNAME, TXT records
- **Caching**: DNS response caching with TTL management
- **Statistics & Metrics**: Comprehensive monitoring and performance metrics

## 🚀 Quick Start

### Complete Architecture Test
```bash
# Run comprehensive test demonstrating full architecture
./test_multi_server_architecture.sh
```

### DNS Gateway with Load Balancing Test
```bash
# Test the new DNS Gateway functionality
./test_dns_gateway.sh
```

### Interactive Architecture Manager
```bash
# Use the comprehensive architecture manager
python dns_architecture_manager.py --mode demo      # Run automated demo
python dns_architecture_manager.py --mode interactive  # Interactive mode
```

### Manual Setup
```bash
# 1. Setup environment
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# 2. Generate keys and certificates
bash generate_tsig_key.sh    # For TSIG authentication
bash generate_certs.sh       # For DoT/DoH

# 3. Start primary server (with TSIG for gateway compatibility)
python -m dns_server.main --port-udp 5353 --port-tcp 5354 \
  --zone dns_server/zones/primary.zone \
  --tsig-name tsig-key-1752130646 \
  --tsig-secret 2vgKc8+OH9UMBrRYTBYOmjffLaCFVtGQPgXjt6fw05k=

# 4. Start secondary servers (in separate terminals)
python -m dns_server.main --port-udp 7353 --port-tcp 7354 --secondary \
  --primary-server 127.0.0.1 --primary-port 5354 \
  --tsig-name tsig-key-1752130646 \
  --tsig-secret 2vgKc8+OH9UMBrRYTBYOmjffLaCFVtGQPgXjt6fw05k= --primary-server 127.0.0.1 --primary-port 5354
python -m dns_server.main --port-udp 8353 --port-tcp 8354 --secondary \
  --primary-server 127.0.0.1 --primary-port 5354 \
  --tsig-name tsig-key-1752130646 \
  --tsig-secret 2vgKc8+OH9UMBrRYTBYOmjffLaCFVtGQPgXjt6fw05k=

# 5. Start DNS Gateway (optional - for load balancing)
python -m dns_server.utils.dns_gateway \
  --listen-port 9353 \
  --backend-servers "127.0.0.1:5353" "127.0.0.1:7353" "127.0.0.1:8353" \
  --tsig-key-name tsig-key-1752130646 \
  --tsig-secret 2vgKc8+OH9UMBrRYTBYOmjffLaCFVtGQPgXjt6fw05k=
```

**Note**: If you plan to use the DNS Gateway, all backend servers must be configured with the same TSIG key to handle signed queries from the gateway.

## Server Configurations

### Important: TSIG Compatibility

If you're using the DNS Gateway, backend servers **must** be configured with TSIG authentication because the gateway signs all forwarded queries. Starting a server without TSIG while a TSIG-enabled gateway is running will result in "got signed message without keyring" errors.

**For Gateway compatibility, always use:**
```bash
# Backend servers for gateway
python -m dns_server.main \
  --port-udp 5353 \
  --zone dns_server/zones/primary.zone \
  --tsig-name tsig-key-1752130646 \
  --tsig-secret 2vgKc8+OH9UMBrRYTBYOmjffLaCFVtGQPgXjt6fw05k=
```

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

### DNS Gateway (Load Balancer + Proxy)
```bash
# Start DNS Gateway with multiple backend servers and TSIG authentication
python -m dns_server.utils.dns_gateway \
  --listen-address 127.0.0.1 \
  --listen-port 9353 \
  --backend-servers "127.0.0.1:5353" "127.0.0.1:7353" "127.0.0.1:8353" \
  --rate-limit-threshold 100 \
  --rate-limit-window 5 \
  --rate-limit-ban 300 \
  --health-check-interval 30 \
  --tsig-key-file dns_server/keys/tsig-key-1752130646.key

# Alternative: Direct TSIG configuration
python -m dns_server.utils.dns_gateway \
  --listen-address 127.0.0.1 \
  --listen-port 9353 \
  --backend-servers "127.0.0.1:5353" \
  --tsig-key-name tsig-key-1752130646 \
  --tsig-key-secret 2vgKc8+OH9UMBrRYTBYOmjffLaCFVtGQPgXjt6fw05k= \
  --require-tsig  # Require TSIG from clients (optional)
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

## 🏗️ Architecture Options

### Option 1: Standalone DNS Server
```
Client → DNS Server (Primary/Secondary)
```
- Single DNS server handling all queries
- Good for: Development, small deployments
- Features: All DNS server features, no load balancing

### Option 2: DNS Server + Gateway
```
Client → DNS Gateway → DNS Server
```
- Gateway acts as proxy and load balancer
- Good for: Medium deployments, DoS protection
- Features: Load balancing, health monitoring, enhanced rate limiting

### Option 3: Multi-Server + Gateway (Enterprise)
```
Client → DNS Gateway → Multiple DNS Servers
                     ├── Primary DNS Server
                     ├── Secondary DNS Server 1  
                     └── Secondary DNS Server 2
```
- Full enterprise architecture with redundancy
- Good for: Production, high availability, high traffic
- Features: Load balancing, automatic failover, zone synchronization

## 🌐 DNS Gateway Features

The DNS Gateway extends your DNS server with enterprise-grade proxy capabilities:

### Load Balancing
- **Round-robin distribution** across multiple backend DNS servers
- **Health monitoring** with automatic failover
- **Server pool management** (add/remove servers dynamically)

### Enhanced Security
- **TSIG Authentication** for secure communication with backend servers
- **Rate limiting** with configurable thresholds and ban durations
- **Access Control Lists** (ACL) integration
- **DoS protection** with IP blocking

### Monitoring & Statistics
- **Real-time statistics** on queries, errors, and backend status
- **Health check reporting** for all backend servers
- **Performance metrics** and load distribution tracking

### High Availability
- **Automatic failover** when backend servers become unavailable
- **Graceful degradation** with remaining healthy servers
- **Backend recovery detection** and automatic re-inclusion

## 🔧 Troubleshooting

### Common Issues

#### "got signed message without keyring" Error

**Problem**: You see this error when a DNS server receives TSIG-signed queries but wasn't configured with TSIG authentication.

**Symptoms**:
```
dns.message.UnknownTSIGKey: got signed message without keyring
```

**Cause**: The DNS Gateway sends TSIG-signed queries to backend servers, but the backend server was started without TSIG configuration.

**Solution**: Always start backend servers with TSIG when using the DNS Gateway:
```bash
# ❌ Wrong: Server without TSIG (will fail with gateway)
python -m dns_server.main --port-udp 5353

# ✅ Correct: Server with TSIG (works with gateway) 
python -m dns_server.main --port-udp 5353 \
  --tsig-name tsig-key-1752130646 \
  --tsig-secret 2vgKc8+OH9UMBrRYTBYOmjffLaCFVtGQPgXjt6fw05k=
```

#### Gateway Health Check Failures

**Problem**: Gateway logs show "Backend server failed health check"

**Cause**: Backend servers not configured with TSIG or using wrong TSIG key

**Solution**: Ensure all backend servers use the same TSIG key as the gateway

#### TSIG Verify Failure

**Problem**: dig shows "Couldn't verify signature: tsig verify failure"

**Cause**: Client and server have mismatched TSIG keys or the response signature is invalid

**Solution**: This is usually cosmetic - the query still works, but check TSIG key consistency

### Best Practices

1. **Consistent TSIG Configuration**: Use the same TSIG key across all servers in your architecture
2. **Test Without Gateway First**: Start with basic server configuration, then add gateway
3. **Check Logs**: Always check logs for specific error messages
4. **Use Test Scripts**: The provided test scripts handle TSIG configuration automatically

## 🛡️ DNS Gatekeeping and Security Features

Your DNS server includes comprehensive gatekeeping functionality to control and secure DNS access:

### Access Control Gatekeeping

#### 1. Network-Based Access Control (ACL)
```bash
# Allow only trusted networks
python -m dns_server.main \
  --zone dns_server/zones/primary.zone \
  --allow 192.168.1.0/24 10.0.0.0/8 \
  --deny 172.16.0.0/12 \
  --port-udp 5353

# Test ACL blocking
dig @127.0.0.1 -p 5353 www.example.com A  # Will timeout if your IP is blocked
```

#### 2. Query-Based Gatekeeping
```bash
# Rate limiting to prevent DoS attacks
python -m dns_server.main \
  --rate-limit-threshold 50 \
  --rate-limit-window 10 \
  --rate-limit-ban-duration 600 \
  --port-udp 5353

# Test rate limiting
python test_rate_limiting.py --test burst  # Triggers protective blocking
```

#### 3. Authentication-Based Gatekeeping
```bash
# TSIG-only server (requires authentication for all queries)
python -m dns_server.main \
  --zone dns_server/zones/primary.zone \
  --tsig-name tsig-key-1752130646 \
  --tsig-secret 2vgKc8+OH9UMBrRYTBYOmjffLaCFVtGQPgXjt6fw05k= \
  --port-udp 5353

# Only authenticated queries work
dig @127.0.0.1 -p 5353 www.example.com A \
  -y tsig-key-1752130646:2vgKc8+OH9UMBrRYTBYOmjffLaCFVtGQPgXjt6fw05k=
```

### Gateway-Level Gatekeeping

#### DNS Gateway as Security Gateway
The DNS Gateway acts as a comprehensive security gateway with multiple protection layers:

```bash
# Start security-focused gateway
python -m dns_server.utils.dns_gateway \
  --listen-port 9353 \
  --backend-servers "127.0.0.1:5353" "127.0.0.1:7353" \
  --rate-limit-threshold 30 \
  --rate-limit-window 5 \
  --rate-limit-ban 900 \
  --tsig-key-file dns_server/keys/tsig-key-1752130646.key \
  --require-tsig  # Optional: Require client TSIG authentication
```

#### Multi-Layer Protection
1. **Client Filtering**: ACL and rate limiting at gateway level
2. **Query Signing**: Automatic TSIG signing of backend queries
3. **Health Monitoring**: Only route to healthy, secure backends
4. **Load Distribution**: Prevent overload on individual servers

### Gatekeeping Test Commands

#### Test Access Control
```bash
# Test network blocking
python -m dns_server.main --deny 127.0.0.0/24 --port-udp 5353 &
dig @127.0.0.1 -p 5353 www.example.com A  # Should timeout (blocked)
```

#### Test Rate Limiting
```bash
# Start rate-limited server
python -m dns_server.main --rate-limit-threshold 5 --rate-limit-window 10 --port-udp 5353 &

# Trigger rate limiting
for i in {1..10}; do 
  dig @127.0.0.1 -p 5353 test$i.example.com A +short; 
done
# Later queries should be blocked
```

#### Test Authentication Gatekeeping
```bash
# TSIG-required server
python -m dns_server.main --tsig-name test-key --tsig-secret dGVzdA== --port-udp 5353 &

# Unauthenticated query (will timeout)
dig @127.0.0.1 -p 5353 www.example.com A

# Authenticated query (will work)
dig @127.0.0.1 -p 5353 www.example.com A -y test-key:dGVzdA==
```

### Gatekeeping Statistics and Monitoring

#### View Protection Statistics
```bash
# Gateway statistics include gatekeeping metrics
curl http://localhost:8080/stats  # If monitoring enabled

# Log analysis for security events
grep "blocked\|denied\|rate limit" logs/*.log
```

#### Security Event Types
- **ACL Violations**: Blocked IP addresses
- **Rate Limit Triggers**: DoS attack mitigation
- **Authentication Failures**: Invalid TSIG signatures
- **Health Check Failures**: Backend server problems

### Integration with External Security Tools

#### Fail2Ban Integration
```bash
# Monitor DNS logs for attacks
# Add to /etc/fail2ban/jail.local:
[dns-dos]
enabled = true
port = 53
protocol = udp
filter = dns-dos
logpath = /path/to/dns/logs/*.log
maxretry = 10
bantime = 3600
```

#### SIEM Integration
- Export security logs in structured format
- Real-time alerting on security events
- Integration with security orchestration platforms
