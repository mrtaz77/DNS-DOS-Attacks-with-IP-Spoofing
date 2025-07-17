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

### 2. UDP Fraggle Attack
- **File**: `attack/udp_fraggle.py`
- **Description**: Network amplification attack using UDP broadcast packets
- **Features**: Broadcast targeting, service amplification, spoofed source IPs
- **Documentation**: `UDP_FRAGGLE_DOCUMENTATION.md`

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
# TCP SYN Flood
python attack/tcp_syn_flood.py

# UDP Fragmented Flood
python attack/udp_fragmented_flood.py

# UDP Fraggle Attack
python attack/udp_fraggle.py
```

### Test Scripts
```bash
# Run interactive test scripts
python tests/test_tcp_syn_flood.py
python tests/test_udp_fragmented_flood.py
python tests/test_udp_fraggle.py
```

### Programmatic Usage
```python
from attack.tcp_syn_flood import TCPSynFlood

# Create attack instance
attack = TCPSynFlood(
    target_ip="192.168.1.100",
    target_port=80,
    duration=60,
    threads=50
)

# Execute attack
attack.attack()
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

## Project Structure

```
DNS-DOS-Attacks-with-IP-Spoofing/
├── attack/
│   ├── attack_strategy.py          # Base class for all attacks
│   ├── constants.py                # Common constants
│   ├── tcp_syn_flood.py           # TCP SYN flood implementation
│   ├── udp_fragmented_flood.py    # UDP fragmented flood implementation
│   ├── udp_fraggle.py             # UDP Fraggle attack implementation
│   ├── icmp_ping_flood.py         # ICMP ping flood (in development)
│   ├── icmp_smurf.py              # ICMP Smurf attack (in development)
│   └── malformed_udp_query_flood.py # Malformed UDP queries (in development)
├── tests/
│   ├── test_tcp_syn_flood.py      # TCP SYN flood test script
│   ├── test_udp_fragmented_flood.py # UDP fragmented flood test script
│   └── test_udp_fraggle.py        # UDP Fraggle test script
├── UDP_FRAGMENTED_FLOOD_DOCUMENTATION.md
├── UDP_FRAGGLE_DOCUMENTATION.md
├── REFACTORING_SUMMARY.md
└── README.md
```

## Documentation

- **UDP_FRAGMENTED_FLOOD_DOCUMENTATION.md**: Detailed UDP fragmented flood attack documentation
- **UDP_FRAGGLE_DOCUMENTATION.md**: Comprehensive UDP Fraggle attack documentation
- **REFACTORING_SUMMARY.md**: Summary of code refactoring and architecture decisions
- **Source Code Comments**: Extensive in-line documentation with RFC-style packet structure diagrams

## Contributing

1. Fork the repository
2. Create a feature branch
3. Implement your attack following the established patterns
4. Add comprehensive documentation
5. Include test scripts
6. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This software is provided for educational and research purposes only. The authors are not responsible for any misuse or damage caused by this software. Users are solely responsible for ensuring they comply with all applicable laws and regulations.

## References

- RFC 791: Internet Protocol
- RFC 793: Transmission Control Protocol
- RFC 768: User Datagram Protocol
- RFC 792: Internet Control Message Protocol
- Various network security and attack mitigation resources
