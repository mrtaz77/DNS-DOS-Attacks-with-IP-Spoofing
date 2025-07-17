# UDP Fragmented Flood Attack Documentation

## Overview

The UDP Fragmented Flood attack is a sophisticated Denial of Service (DoS) attack that exploits the IP fragmentation mechanism. This attack sends large UDP packets that are intentionally fragmented at the IP layer, forcing the target system to consume significant resources reassembling the fragments.

## Attack Mechanics

### How IP Fragmentation Works

1. **Original Packet**: A large UDP packet (1500-8000 bytes) is created
2. **Fragmentation**: The packet is split into smaller fragments (≤1480 bytes each)
3. **Fragment Headers**: Each fragment gets its own IP header with fragmentation information
4. **Reassembly**: The target must collect all fragments and reassemble the original packet

### Attack Strategy

- **Resource Exhaustion**: Forces target to allocate memory for partial packets
- **Processing Overhead**: Out-of-order fragments increase CPU usage
- **Buffer Consumption**: Incomplete fragments consume reassembly buffers
- **Timeout Exploitation**: Fragments that never complete waste resources until timeout

## Packet Structure Details

### IP Header Fields (20 bytes)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version|  IHL  |Type of Service|          Total Length         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Identification        |Flags|      Fragment Offset    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Time to Live |    Protocol   |         Header Checksum       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Source Address                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Destination Address                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**Key Fields for Fragmentation:**
- **Identification**: Same for all fragments of one packet
- **Flags**: Don't Fragment (DF) = 0, More Fragments (MF) = 1 (except last)
- **Fragment Offset**: Position in original packet (in 8-byte units)

### UDP Header Fields (8 bytes) - First Fragment Only

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Source Port          |       Destination Port        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            Length             |           Checksum            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

## Implementation Features

### 1. **Intelligent Fragmentation**
- Calculates optimal fragment sizes based on MTU
- Ensures fragments are large enough to cause processing overhead
- Maintains proper fragment offset calculations

### 2. **Out-of-Order Delivery**
- Fragments are sent in random order
- Increases reassembly complexity
- Maximizes processing overhead on target

### 3. **IP Spoofing**
- Uses random source IP addresses
- Makes filtering and blocking difficult
- Distributed appearance of attack traffic

### 4. **Configurable Parameters**
- Fragment size (default: 1480 bytes)
- Original packet size range (1500-8000 bytes)
- Number of threads and attack duration
- Target IP and port configuration

## Attack Effectiveness

### Target Impact
- **Memory Consumption**: Reassembly buffers filled with partial packets
- **CPU Usage**: Increased processing for fragment handling
- **Network Performance**: Bandwidth consumed by fragmented traffic
- **Service Degradation**: Legitimate traffic may be dropped

### Effectiveness Metrics
- **High Intensity**: >1000 fragments per second
- **Medium Intensity**: 500-1000 fragments per second
- **Low Intensity**: <500 fragments per second

## Usage Example

```python
from udp_fragmented_flood import FragmentedUDPFlood

# Create attack instance
attack = FragmentedUDPFlood(
    target_ip="192.168.1.100",
    target_port=53,           # DNS port
    duration=30,              # 30 seconds
    threads=5                 # 5 worker threads
)

# Execute the attack
attack.attack()
```

## Configuration Options

### Attack Parameters
- **target_ip**: Target server IP address
- **target_port**: Target service port
- **duration**: Attack duration in seconds
- **threads**: Number of concurrent threads

### Fragment Configuration
- **fragment_size**: Maximum fragment payload size (default: 1480)
- **max_packet_size**: Maximum original packet size (default: 8000)
- **min_packet_size**: Minimum packet size to ensure fragmentation (default: 1500)

## Defensive Measures

### Network-Level Defenses
1. **Fragment Filtering**: Drop fragmented packets at firewall
2. **Rate Limiting**: Limit fragments per second per source
3. **Reassembly Timeout**: Reduce fragment timeout values
4. **Buffer Management**: Implement fragment buffer limits

### System-Level Defenses
1. **Resource Limits**: Set maximum reassembly buffer size
2. **Priority Queuing**: Prioritize complete packets over fragments
3. **Fragment Inspection**: Deep packet inspection of fragments
4. **Anomaly Detection**: Monitor fragment patterns for attacks

## Legal and Ethical Considerations

⚠️ **WARNING**: This implementation is for educational purposes only!

### Legal Requirements
- Only use on systems you own or have explicit permission to test
- Unauthorized use may violate computer crime laws
- Always follow responsible disclosure practices
- Respect network policies and terms of service

### Ethical Guidelines
- Use in controlled lab environments only
- Do not target production systems
- Implement proper safeguards and monitoring
- Consider impact on network infrastructure

## Technical Limitations

### Implementation Constraints
- Requires administrator/root privileges for raw sockets
- May be blocked by modern firewalls
- Performance depends on system capabilities
- Network conditions affect fragment delivery

### Detection Possibilities
- Unusual fragment patterns may be detected
- High fragment rates can trigger alarms
- Source IP spoofing may be filtered
- Deep packet inspection can identify attacks

## Educational Value

This implementation demonstrates:
- IP fragmentation mechanics and vulnerabilities
- Network packet crafting and manipulation
- Resource exhaustion attack techniques
- The importance of proper fragment handling
- Network security defensive strategies

Understanding these concepts helps network administrators:
- Implement effective fragment filtering
- Configure appropriate timeout values
- Monitor for fragmentation-based attacks
- Design resilient network architectures

## References

- RFC 791: Internet Protocol Specification
- RFC 768: User Datagram Protocol
- RFC 1191: Path MTU Discovery
- Network Security Best Practices Documentation
