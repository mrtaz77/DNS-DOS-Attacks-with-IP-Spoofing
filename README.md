# DNS-DOS-Attacks-with-IP-Spoofing

A comprehensive collection of DoS/DDoS attack simulations with IP spoofing capabilities for educational and security testing purposes.

## Overview

This project implements various types of Denial of Service (DoS) and Distributed Denial of Service (DDoS) attacks with IP spoofing capabilities. The implementation focuses on educational value, code reusability, and proper security testing practices.

## Features

- **Multiple Attack Types**: UDP Fragmented Flood, DNS Random Subdomain Query Flood, and more
- **IP Spoofing**: All attacks implement proper IP spoofing techniques
- **Multi-threading**: Configurable concurrent attack threads
- **Comprehensive Logging**: Detailed logging with colored output
- **Raw Socket Programming**: Low-level packet crafting and manipulation
- **Attack Simulations**: Complete simulation environments with impact analysis
- **Educational Documentation**: Detailed explanations of attack mechanisms and packet structures

## Implemented Attacks

### 1. UDP Fragmented Flood Attack
- **File**: `attack/udp_fragmented_flood.py`
- **Description**: Sends fragmented UDP packets with spoofed source IPs to overwhelm fragment reassembly buffers
- **Features**: Out-of-order fragment delivery, proper fragmentation handling, memory exhaustion
- **Simulation**: `udp_fragment_attack_simulation.py` - Complete 4-thread simulation environment

### 2. DNS Random Subdomain Query Flood
- **File**: `attack/dns_random_subdomain_query_flood.py`  
- **Description**: Floods DNS servers with random subdomain queries causing cache misses and processing overhead
- **Features**: IP spoofing, random subdomain generation, multiple query types, cache bypass
- **Simulation**: `dns_random_subdomain_attack_simulation.py` - Complete 5-thread simulation environment

### Common Features
- **Logging**: Centralized logging with different severity levels
- **Colored Output**: Visual feedback with colored terminal output
- **IP Spoofing**: Reusable IP spoofing utilities
- **Checksum Calculation**: Proper packet checksum computation
- **Privilege Checking**: Raw socket privilege validation

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/DNS-DOS-Attacks-with-IP-Spoofing.git
cd DNS-DOS-Attacks-with-IP-Spoofing
```

2. Install dependencies:
```bash
pip install colorama dnspython
```

3. Run with administrative privileges (required for raw sockets)

## Usage

### Loopback aliases
```sh
# Add private IPs to loopback interface
sudo ip addr add 192.168.100.10/32 dev lo
sudo ip addr add 192.168.100.20/32 dev lo

# Verify they're added
ip addr show lo

# Test connectivity
ping 192.168.100.10
ping 192.168.100.20
```

### Normal Client Simulation
```py
python simulation/client/client.py --server-ip <server_ip> --server-port <server_port> --zone <zone_file> --addr <client_ip> --log <client_log_file>
```

### DNS Reply Flood Attack
```bash
sudo python -m simulation.attacker.attack --server-ip <server_ip> --server-port <server_port> --target-ip <target_ip> --duration <duration> --threads <num_threads> --log-file <log_file>
```

### High-Performance DNS Server
The project includes an improved DNS server implementation optimized for high-volume scenarios:

```bash
# Start high-performance DNS server
python -m dns_server.main \
  --port-udp 5353 \
  --rate-limit-threshold 1000000 \
  --max-workers 200 \
  --queue-size 5000 \
  --cache-type lru \
  --cache-size 50000

# Monitor server performance in real-time
python dns_server_monitor.py --server-port 5353 --interval 1

# Test server under high load
python test_high_volume_dns.py --requests 100000 --workers 500 --server-port 5353

# Run improvement demonstration
python dns_improvement_demo.py
```

#### Server Performance Features
- **Thread Pool Management**: Configurable worker threads (default: 50, max recommended: 200)
- **Request Queue**: Bounded queue to prevent memory exhaustion (default: 1000)
- **Advanced Rate Limiting**: Sliding window algorithm with memory-efficient cleanup
- **High-Volume Optimizations**: Handles millions of requests without thread exhaustion
- **Real-time Monitoring**: Built-in statistics and performance tracking
sudo python -m simulation.attacker.attack --server-ip <server_ip> --server-port <server_port> --target-ip <target_ip> --duration <duration> --threads <num_threads> --log-file <log_file>
```

### Direct Attack Execution
```bash
# UDP Fragmented Flood
sudo python attack/udp_fragmented_flood.py

# DNS Random Subdomain Query Flood  
sudo python attack/dns_random_subdomain_query_flood.py
```

### Attack Simulations (Recommended)

#### UDP Fragment Attack Simulation
Complete 4-thread simulation demonstrating UDP fragmentation attack impact:

```bash
# Basic simulation (30 second attack)
sudo python udp_fragment_attack_simulation.py --duration 30 --threads 10

# Advanced configuration
sudo python udp_fragment_attack_simulation.py \
  --duration 60 \
  --threads 25 \
  --target-ip 127.0.0.1 \
  --target-port 5353 \
  --min-size 2000 \
  --max-size 8000 \
  --verbose

# Custom packet size range for specific fragment testing
sudo python udp_fragment_attack_simulation.py \
  --min-size 1500 \
  --max-size 6000 \
  --duration 45
```

**Simulation Components:**
- **Thread 1**: DNS Server (Target victim)
- **Thread 2**: Normal Client (Experiences service degradation)
- **Thread 3**: UDP Fragment Attack (Sends fragmented packets)
- **Thread 4**: Fragment DoS Monitor (Measures attack impact)

#### DNS Subdomain Flood Attack Simulation
Complete 5-thread simulation demonstrating DNS subdomain flood attack:

```bash
# Basic simulation (60 second attack)
sudo python dns_random_subdomain_attack_simulation.py --duration 60 --threads 15

# Advanced configuration
sudo python dns_random_subdomain_attack_simulation.py \
  --duration 90 \
  --threads 20 \
  --target-port 5353 \
  --auth-port 6353 \
  --server-ip 127.0.0.1 \
  --verbose

# Quick test (30 seconds)
sudo python dns_random_subdomain_attack_simulation.py \
  --duration 30 \
  --threads 10
```

**Simulation Components:**
- **Thread 1**: Target DNS Server (Recursive resolver - Primary victim)
- **Thread 2**: Authoritative DNS Server (Unwitting amplification participant)
- **Thread 3**: Legitimate DNS Client (Collateral victim)
- **Thread 4**: DNS Subdomain Flood Attack (The attacker)
- **Thread 5**: DoS Impact Monitoring (Attack detection and analysis)

### Test Scripts
```bash
# Individual attack testing
python tests/test_udp_fragmented_flood.py
python tests/test_dns_random_subdomain_query_flood.py
```

## Simulation Output and Analysis

### Log Files Generated
Both simulations create comprehensive logs in the `logs/` directory:

**UDP Fragment Simulation:**
- `dns_server_fragment_attack.log` - DNS server under fragment attack
- `client_requests_during_fragment_attack.log` - Client experience during attack
- `udp_fragment_attack.log` - Attack execution details
- `fragment_dos_monitoring.log` - DoS impact measurements
- `udp_fragment_simulation_report.json` - Comprehensive analysis report

**DNS Subdomain Flood Simulation:**
- `target_dns_server.log` - Target DNS server activity  
- `auth_dns_server.log` - Authoritative server responses
- `legitimate_client.log` - Client experience during attack
- `attack.log` - Attack execution details
- `dos_monitoring.log` - Service degradation metrics
- `dns_simulation_report.json` - Comprehensive analysis report

### Metrics Collected

**Performance Metrics:**
- Response time analysis (baseline vs attack vs recovery)
- Failure rate percentages
- Timeout detection
- Service degradation indicators

**Attack Impact Metrics:**
- Packets/queries sent
- Estimated fragments generated (UDP)
- NXDOMAIN responses (DNS)
- Memory pressure indicators
- Amplification factors

**Client Impact Metrics:**
- Success/failure rates
- Response time degradation
- Service disruption detection

## Configuration

### Attack Parameters
- **target_ip**: Target IP address (default: 127.0.0.1)
- **target_port**: Target port number (default: 5353 for simulations)
- **duration**: Attack duration in seconds
- **threads**: Number of concurrent attack threads

### DNS Server Performance Tuning

#### For High-Volume Testing (Recommended Settings)
```bash
python -m dns_server.main \
  --rate-limit-threshold 10000000 \
  --max-workers 200 \
  --queue-size 5000 \
  --cache-type lru \
  --cache-size 100000
```

#### For Production Environments
```bash
python -m dns_server.main \
  --rate-limit-threshold 1000 \
  --max-workers 50 \
  --queue-size 1000 \
  --cache-type hybrid \
  --redis-url redis://localhost:6379/0
```

#### For Development/Testing
```bash
python -m dns_server.main \
  --rate-limit-threshold 100 \
  --max-workers 20 \
  --queue-size 500
```

#### Performance Parameters
- **max-workers**: Maximum worker threads (5-200, default: 50)
  - Higher values handle more concurrent requests
  - Too high may cause thread contention
- **queue-size**: Request queue size (100-5000, default: 1000)  
  - Larger queues handle traffic bursts better
  - Too large may consume excessive memory
- **rate-limit-threshold**: Requests per IP per time window
  - Set high (1M+) for attack testing
  - Set low (100-1000) for production protection

### UDP Fragment Specific
- **min_packet_size**: Minimum fragmented packet size (default: 1500)
- **max_packet_size**: Maximum fragmented packet size (default: 8000)

### DNS Subdomain Flood Specific  
- **auth_port**: Authoritative DNS server port (default: 6353)
- **base_domains**: Domain list for subdomain generation
- **query_types**: DNS query types (A, AAAA, MX, CNAME, NS, TXT)

### Logging Configuration
- Log files are created in the `logs/` directory
- Configurable log levels: DEBUG, INFO, WARNING, ERROR
- Colored terminal output for real-time monitoring
- JSON reports for detailed analysis

## Attack Mechanism Details

### UDP Fragmented Flood
1. **Large Packet Generation**: Creates UDP packets larger than MTU (1500+ bytes)
2. **IP Fragmentation**: IP layer automatically fragments packets
3. **Out-of-Order Delivery**: Sends fragments in random order
4. **Memory Exhaustion**: Forces target to allocate reassembly buffers
5. **Resource Depletion**: Overwhelms fragment timeout and cleanup mechanisms

### DNS Random Subdomain Query Flood
1. **Random Subdomain Generation**: Creates queries like `abc123.example.com`
2. **IP Spoofing**: Each query appears from different source IP
3. **Cache Bypass**: Random subdomains ensure cache misses
4. **Recursive Overhead**: Forces expensive authoritative lookups
5. **Processing Exhaustion**: Overwhelms DNS resolver capacity

## Prerequisites

### System Requirements
- **Operating System**: Linux, Windows (with administrator privileges), macOS
- **Python**: 3.7+ with dnspython and colorama packages
- **Privileges**: Administrator/root access for raw socket creation
- **Network**: Local network access for testing

### DNS Server Requirements
The simulations require a DNS server implementation. Ensure you have:
- DNS server module in `dns_server/` directory
- Zone files in `dns_server/zones/`
- Python DNS server implementation

## Security Considerations

### Legal and Ethical Use
⚠️ **WARNING**: This software is for educational and authorized testing purposes only.

- Only use against systems you own or have explicit permission to test
- Respect network policies and local laws
- Consider the impact on network resources and other users
- Use in controlled environments only

### Defensive Measures
- **Ingress Filtering**: Implement BCP38 to prevent IP spoofing
- **Rate Limiting**: Deploy traffic shaping and connection limits
- **Fragment Protection**: Configure fragment reassembly timeouts
- **DNS Security**: Implement response rate limiting (RRL)
- **Monitoring**: Deploy intrusion detection systems
- **Load Balancing**: Use DNS load balancers and anycast

### Attack Detection Indicators

**UDP Fragment Attack:**
- High fragment reassembly failures
- Memory pressure on target systems
- Unusual fragment patterns in network traffic
- Increased response times for legitimate traffic

**DNS Subdomain Flood:**
- High NXDOMAIN response rates
- Random subdomain query patterns
- Distributed source IP addresses
- DNS cache pollution
- Authoritative server overload

## Troubleshooting

### Common Issues

**Permission Denied:**
```bash
# Ensure running with administrator privileges
sudo python udp_fragment_attack_simulation.py
# or
python dns_random_subdomain_attack_simulation.py  # Run as administrator on Windows
```

**DNS Server Not Starting:**
- Check if ports 5353/6353 are available
- Verify DNS server module installation
- Check zone file configuration

**Raw Socket Errors:**
- Verify administrator/root privileges
- Check firewall settings
- Ensure raw socket support in OS

### Performance Tuning

**For High-Impact Testing:**
- Increase thread count (--threads 50)
- Extend attack duration (--duration 300)
- Adjust packet sizes for fragments (--max-size 65000)

**For Development Testing:**
- Reduce thread count (--threads 5)
- Shorter duration (--duration 10)
- Enable verbose logging (--verbose)

## Disclaimer

This software is provided for educational and research purposes only. The authors are not responsible for any misuse or damage caused by this software. Users are solely responsible for ensuring they comply with all applicable laws and regulations.

## References

- RFC 791: Internet Protocol
- RFC 793: Transmission Control Protocol  
- RFC 768: User Datagram Protocol
- RFC 1035: Domain Names - Implementation and Specification
- RFC 3833: Threat Analysis of the Domain Name System
- BCP 38: Network Ingress Filtering
- Various network security and attack mitigation resources

## Contributing

Please ensure any contributions follow responsible disclosure principles and include appropriate warnings about ethical use.