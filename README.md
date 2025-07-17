# DNS-DOS-Attacks-with-IP-Spoofing

A comprehensive collection of DoS/DDoS attack simulations with IP spoofing capabilities for educational and security testing purposes.

## Overview

This project implements various types of Denial of Service (DoS) and Distributed Denial of Service (DDoS) attacks with IP spoofing capabilities. The implementation focuses on educational value, code reusability, and proper security testing practices.

## Features

- **Multiple Attack Types**: TCP SYN Flood, UDP Fragmented Flood, UDP Fraggle, ICMP attacks, and more
- **IP Spoofing**: All attacks implement proper IP spoofing techniques
- **Multi-threading**: Configurable concurrent attack threads
- **Comprehensive Logging**: Detailed logging with colored output
- **Raw Socket Programming**: Low-level packet crafting and manipulation
- **Educational Documentation**: Detailed explanations of attack mechanisms and packet structures

## Implemented Attacks

### 1. UDP Fragmented Flood Attack
- **File**: `attack/udp_fragmented_flood.py`
- **Description**: Sends fragmented UDP packets with spoofed source IPs
- **Features**: Out-of-order fragment delivery, proper fragmentation handling
- **Documentation**: `UDP_FRAGMENTED_FLOOD_DOCUMENTATION.md`

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
pip install colorama
```

3. Run with administrative privileges (required for raw sockets)

## Usage

### Direct Execution
```bash
# UDP Fragmented Flood
python attack/udp_fragmented_flood.py

```

### Test Scripts
```bash
python tests/test_udp_fragmented_flood.py
```

## Configuration

### Attack Parameters
- **target_ip**: Target IP address
- **target_port**: Target port number
- **duration**: Attack duration in seconds
- **threads**: Number of concurrent threads

### Logging Configuration
- Log files are created in the same directory as the attack scripts
- Configurable log levels: DEBUG, INFO, WARNING, ERROR
- Colored terminal output for real-time monitoring

## Security Considerations

### Legal and Ethical Use
⚠️ **WARNING**: This software is for educational and authorized testing purposes only.

- Only use against systems you own or have explicit permission to test
- Respect network policies and local laws
- Consider the impact on network resources and other users
- Use in controlled environments only

### Defensive Measures
- Implement ingress filtering to prevent IP spoofing
- Use rate limiting and traffic shaping
- Monitor for unusual traffic patterns
- Deploy intrusion detection systems

## Disclaimer

This software is provided for educational and research purposes only. The authors are not responsible for any misuse or damage caused by this software. Users are solely responsible for ensuring they comply with all applicable laws and regulations.

## References

- RFC 791: Internet Protocol
- RFC 793: Transmission Control Protocol
- RFC 768: User Datagram Protocol
- RFC 792: Internet Control Message Protocol
- Various network security and attack mitigation resources
