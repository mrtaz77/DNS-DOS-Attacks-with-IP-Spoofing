# DNS-DOS-Attacks-with-IP-Spoofing
Dos attacks against dns server using ip spoofing

## Overview
This project implements a full-featured DNS server (UDP, TCP, DNS-over-TLS, DNS-over-HTTPS) with support for zone files, caching, ACLs, TSIG authentication, and DNSSEC signing.

## Installation
1. Clone the repo:
   ```bash
   git clone <repo_url>
   cd DNS-DOS-Attacks-with-IP-Spoofing
   ```
2. Create a Python virtual environment and activate it:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Install BIND utilities (for TSIG key generation):
   ```bash
   # Debian/Ubuntu
   sudo apt-get update && sudo apt-get install -y bind9utils
   # CentOS/RHEL
   sudo yum install -y bind-utils
   ```

## Generating TLS Certificates
To enable DNS-over-TLS (DoT) and DNS-over-HTTPS (DoH), generate a self-signed certificate:
```bash
bash generate_certs.sh
```
The script creates:
- `dns_server/certs/cert.pem`
- `dns_server/certs/key.pem`

## Generating a TSIG Key
To use TSIG authentication for dynamic updates or zone transfers, generate a TSIG key:
```bash
bash generate_tsig_key.sh
```
The script will output a key name and a base64 secret. Use these values with the `--tsig-name` and `--tsig-secret` options when starting the server.

## Zone Files
Edit or add zone files under `dns_server/zones/`. By default, `primary.zone` is loaded as the primary zone.

## Running the DNS Server Locally
Start all supported servers with:
```bash
python3 -m dns_server.main \
  --zone dns_server/zones/primary.zone \
  --keyfile dns_server/certs/key.pem \
  --certfile dns_server/certs/cert.pem \
  --certkey dns_server/certs/key.pem \
  --tsig-name "<KEY_NAME>" \
  --tsig-secret "<SECRET>" \
  --addr 0.0.0.0
```
> Note: binding to port 53 requires root privileges. If you see `Permission denied`, either:
> - Run the command with `sudo`, e.g.:
>   ```bash
>   sudo python3 -m dns_server.main ...
>   ```
> - Or bind to non-privileged ports (>1024):
>   ```bash
>   python3 -m dns_server.main --port-udp 5353 --port-tcp 5353 ...
>   ```

Options:
- `--zone`: Path to zone file
- `--keyfile`: PEM file for DNSSEC
- `--certfile`/`--certkey`: TLS cert/key PEM for DoT/DoH
- `--tsig-name`/`--tsig-secret`: TSIG authentication
- `--forwarder`: Upstream DNS forwarder IP (optional)
- `--allow`/`--deny`: ACL CIDR rules (optional)

## Running Multiple DNS Instances
You can run a primary (master) and one or more secondary (slave) servers to support zone transfers.

### Primary Server
In one terminal, start the primary zone (handles updates and notifies secondaries):
```bash
python3 -m dns_server.main \
  --zone dns_server/zones/primary.zone \
  --keyfile dns_server/certs/key.pem \
  --tsig-name <keyname> \
  --tsig-secret <secret> \
  --addr 0.0.0.0
```

### Secondary Server
In another terminal (or on a different host), start the secondary server pointing at the primary as a forwarder for AXFR:
```bash
python3 -m dns_server.main \
  --zone dns_server/zones/secondary.zone \
  --forwarder <PRIMARY_IP> \
  --tsig-name <keyname> \
  --tsig-secret <secret> \
  --addr 0.0.0.0
```

- Ensure `secondary.zone` has the same `$ORIGIN` and NS records as the primary.
- The secondary will perform an AXFR from the primary and serve the delegated zone.

## DNS Query Testing Guide

This section provides comprehensive examples for testing your DNS server with various query types and scenarios.

### Basic Query Syntax
```bash
dig [@server] [-p port] [domain] [record-type] [options]
```

### 1. Testing A Records (IPv4 Addresses)

#### Existing A Records
```bash
# Test www.example.com
dig @127.0.0.1 -p15353 www.example.com A
# Expected: 192.168.1.2

# Test name server
dig @127.0.0.1 -p15353 ns1.example.com A
# Expected: 192.168.1.1

# Short output format
dig @127.0.0.1 -p15353 www.example.com A +short
# Expected: 192.168.1.2
```

#### Nonexistent A Records
```bash
dig @127.0.0.1 -p15353 nonexistent.example.com A
# Expected: status: NXDOMAIN, no ANSWER section
```

### 2. Testing SOA Records (Start of Authority)
```bash
dig @127.0.0.1 -p15353 example.com SOA
# Expected: ns1.example.com. admin.example.com. 2021120901 3600 1800 604800 3600
```

### 3. Testing NS Records (Name Server)
```bash
dig @127.0.0.1 -p15353 example.com NS
# Expected: ns1.example.com.
```

### 4. Testing MX Records (Mail Exchange)
```bash
dig @127.0.0.1 -p15353 www.example.com MX
# Expected: 10 mail.example.com.
```

### 5. Testing Nonexistent Record Types

#### AAAA Records (IPv6 - not defined in zone)
```bash
dig @127.0.0.1 -p15353 www.example.com AAAA
# Expected: status: NXDOMAIN
```

#### CNAME Records (not defined in zone)
```bash
dig @127.0.0.1 -p15353 www.example.com CNAME
# Expected: status: NXDOMAIN
```

#### TXT Records (not defined in zone)
```bash
dig @127.0.0.1 -p15353 example.com TXT
# Expected: status: NXDOMAIN
```

### 6. Advanced Query Options

#### Query All Available Records
```bash
dig @127.0.0.1 -p15353 www.example.com ANY
# Returns all record types for the domain
```

#### Force TCP Query
```bash
dig @127.0.0.1 -p15353 www.example.com A +tcp
# Uses TCP instead of UDP
```

#### No Recursion
```bash
dig @127.0.0.1 -p15353 www.example.com A +norecurse
# Disables recursive queries
```

#### Show Query Statistics
```bash
dig @127.0.0.1 -p15353 www.example.com A +stats
# Shows query time and other statistics
```

### 7. Testing Cache Functionality
```bash
# First query (will be cached)
dig @127.0.0.1 -p15353 www.example.com MX

# Second query (should hit cache)
dig @127.0.0.1 -p15353 www.example.com MX
```
Check server logs to see "Cache hit" messages for the second query.

### 8. Alternative DNS Query Tools

#### Using nslookup
```bash
# Basic lookup
nslookup www.example.com 127.0.0.1

# Specific record type
nslookup -type=MX www.example.com 127.0.0.1
nslookup -type=SOA example.com 127.0.0.1
```

#### Using host command
```bash
# Basic lookup
host www.example.com 127.0.0.1

# Specific record type
host -t MX www.example.com 127.0.0.1
host -t SOA example.com 127.0.0.1
```

### 9. Understanding DNS Response Codes

#### NOERROR (Success)
- **Status**: `status: NOERROR`
- **When**: Record exists and is returned successfully
- **Example**: `dig @127.0.0.1 -p15353 www.example.com A`

#### NXDOMAIN (Domain doesn't exist)
- **Status**: `status: NXDOMAIN`
- **When**: Queried domain/record doesn't exist in the zone
- **Example**: `dig @127.0.0.1 -p15353 nonexistent.example.com A`

#### SERVFAIL (Server failure)
- **Status**: `status: SERVFAIL`
- **When**: DNS server encounters an internal error
- **Troubleshooting**: Check server logs for error messages

#### REFUSED (Query refused)
- **Status**: `status: REFUSED`
- **When**: Server refuses to answer (often due to ACL restrictions)
- **Troubleshooting**: Check ACL configuration

### 10. Zone Content Summary

Your DNS server hosts the following records in the `example.com` zone:

| Record Type | Name | Value |
|-------------|------|-------|
| SOA | example.com | ns1.example.com. admin.example.com. |
| NS | example.com | ns1.example.com. |
| A | www.example.com | 192.168.1.2 |
| A | ns1.example.com | 192.168.1.1 |
| A | ns3.example.com | 192.168.1.9 |
| A | ns4.example.com | 192.168.1.9 |
| A | ns5.example.com | 192.168.1.4 |
| A | ns7.example.com | 192.168.1.8 |
| A | ns8.example.com | 192.168.2.1 |
| MX | www.example.com | 10 mail.example.com. |

### 11. Troubleshooting Common Issues

#### Timeout Errors
```bash
# If you see: "communications error to 127.0.0.1#15353: timed out"
# Check if server is running:
ps aux | grep dns_server

# Check if port is listening:
ss -tulnp | grep :15353
```

#### NXDOMAIN for Existing Records
- Verify zone file format (should have `$TTL` directive)
- Check server logs for zone loading errors
- Ensure record names match exactly (including trailing dots)

#### Server Won't Start
- Install required Python packages: `pip install -r requirements.txt`
- Check for syntax errors in zone files
- Ensure proper permissions on certificate files

## Next Steps
- Deploy on Azure VM for testing DoS attacks with IP spoofing
- Extend zones, add secondary/slave zones
- Integrate metrics collection or monitoring dashboards
