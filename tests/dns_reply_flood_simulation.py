import subprocess
import time
import threading
import sys
import os
import queue
import logging
import signal
from datetime import datetime
import dns.message
import dns.query
from statistics import mean
import argparse

LOGGING_DIR = "dns-reply-flood"


class DNSReplyFloodSimulation:
    def __init__(
        self,
        attack_duration=60,
        attack_threads=10,
        server_port=5353,
        server_ip="127.0.0.1",
        spoofed_client_ip="192.168.1.200",
        spoofed_client_port=12345,
    ):
        self.dns_server_process = None
        self.stop_event = threading.Event()
        self.results_queue = queue.Queue()
        self.server_ip = server_ip
        self.server_port = server_port
        self.attack_duration = attack_duration
        self.attack_threads = attack_threads
        self.spoofed_client_ip = spoofed_client_ip
        self.spoofed_client_port = spoofed_client_port
        self.metrics = {
            "baseline": [],
            "during_attack": [],
            "post_attack": [],
            "client_requests": [],
            "attack_stats": {},
        }
        self.legitimate_domains = [
            "www.example.com",
            "ns1.example.com",
            "mail.example.com",
            "test.example.com",
            "batch-test1.example.com",
            "batch-test2.example.com",
        ]
        os.makedirs(f"{LOGGING_DIR}", exist_ok=True)

        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - %(threadName)s - %(levelname)s - %(message)s",
            handlers=[
                logging.FileHandler(f"{LOGGING_DIR}/dns_reply_flood_simulation.log"),
                logging.StreamHandler(),
            ],
        )

    def start_dns_server_thread(self):
        thread_name = "DNS-Server"
        logging.info(f"[{thread_name}] Starting DNS server on port {self.server_port}")
        try:
            self.dns_server_process = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "dns_server.main",
                    "--zone",
                    "dns_server/zones/primary.zone",
                    "--addr",
                    self.server_ip,
                    "--port-udp",
                    str(self.server_port),
                    "--port-tcp",
                    str(self.server_port + 1),
                    "--rate-limit-threshold",
                    "100",
                    "--rate-limit-window",
                    "10",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                bufsize=1,
            )
            with open(f"{LOGGING_DIR}/dns_server.log", "w") as log_file:
                log_file.write(f"DNS Server started at {datetime.now()}\n")
                log_file.write("Role: Victim DNS server\n")
                log_file.write("=" * 60 + "\n")
                while (
                    not self.stop_event.is_set()
                    and self.dns_server_process.poll() is None
                ):
                    output = self.dns_server_process.stdout.readline()
                    if output:
                        log_file.write(f"[{datetime.now()}] {output.strip()}\n")
                        log_file.flush()
        except Exception as e:
            logging.error(f"[{thread_name}] Failed to start DNS server: {e}")
            self.results_queue.put(("dns_server_error", str(e)))

    def _determine_phase(self, elapsed_time):
        if elapsed_time < 15:
            return "BASELINE"
        elif elapsed_time < (15 + self.attack_duration):
            return "DURING_ATTACK"
        else:
            return "POST_ATTACK"

    def _send_dns_query_and_time(self, query_name):
        query = dns.message.make_query(query_name, "A")
        start_time = time.time()
        dns.query.udp(query, self.server_ip, port=self.server_port, timeout=5)
        end_time = time.time()
        return (end_time - start_time) * 1000  # ms

    def client_thread(self):
        thread_name = "Legitimate-Client"
        logging.info(f"[{thread_name}] Starting client requests")
        time.sleep(5)
        request_count = 0
        phase_start_time = time.time()
        with open(f"{LOGGING_DIR}/client.log", "w") as log_file:
            log_file.write(f"Legitimate DNS Client started at {datetime.now()}\n")
            log_file.write("Role: Normal user (whose IP is spoofed by attacker)\n")
            log_file.write("=" * 60 + "\n")
            while not self.stop_event.is_set():
                query_name = self.legitimate_domains[
                    request_count % len(self.legitimate_domains)
                ]
                elapsed = time.time() - phase_start_time
                phase = self._determine_phase(elapsed).lower()
                try:
                    response_time = self._send_dns_query_and_time(query_name)
                    log_entry = f"[{datetime.now()}] [{phase}] Query {request_count}: {query_name} -> {response_time:.2f}ms\n"
                    log_file.write(log_entry)
                    log_file.flush()
                    self.metrics[phase].append(response_time)
                    self.metrics["client_requests"].append(
                        {
                            "timestamp": time.time(),
                            "query": query_name,
                            "response_time_ms": response_time,
                            "status": "SUCCESS",
                            "phase": phase,
                        }
                    )
                except Exception as e:
                    log_entry = f"[{datetime.now()}] [{phase}] Query {request_count}: {query_name} FAILED - {e}\n"
                    log_file.write(log_entry)
                    log_file.flush()
                    self.metrics["client_requests"].append(
                        {
                            "timestamp": time.time(),
                            "query": query_name,
                            "response_time_ms": 0,
                            "status": "FAILED",
                            "phase": phase,
                            "error": str(e),
                        }
                    )
                request_count += 1
                time.sleep(2)

    def dns_reply_flood_attack_thread(self):
        thread_name = "DNS-Reply-Flood-Attack"
        logging.info(f"[{thread_name}] Preparing DNS Reply Flood attack")
        time.sleep(15)  # Wait for baseline
        logging.warning(f"[{thread_name}] 🚨 LAUNCHING DNS REPLY FLOOD ATTACK!")
        try:
            sys.path.append(".")
            from attack.dns_reply_flood import DNSReplyFlood

            attack = DNSReplyFlood(
                server_ip=self.server_ip,
                server_port=self.server_port,
                target_ip=self.spoofed_client_ip,
                target_port=self.spoofed_client_port,
                duration=self.attack_duration,
                threads=self.attack_threads,
            )
            with open(f"{LOGGING_DIR}/attack.log", "w") as log_file:
                log_file.write(f"DNS Reply Flood Attack started at {datetime.now()}\n")
                log_file.write("=" * 60 + "\n")
                log_file.write(f"Target: {self.server_ip}:{self.server_port}\n")
                log_file.write(f"Spoofed IP: {self.spoofed_client_ip}\n")
                log_file.write(f"Duration: {self.attack_duration} seconds\n")
                log_file.write(f"Threads: {self.attack_threads}\n")
                log_file.write(
                    "Attack Mechanism: Spoofed IP, high volume of legitimate queries\n"
                )
                log_file.write("=" * 60 + "\n")
            attack_start = time.time()
            attack.attack()
            attack_end = time.time()
            with open(f"{LOGGING_DIR}/attack.log", "a") as log_file:
                log_file.write(
                    f"\nDNS Reply Flood attack completed at {datetime.now()}\n"
                )
                log_file.write(
                    f"Actual duration: {attack_end - attack_start:.2f} seconds\n"
                )
                log_file.write(f"DNS queries sent: {attack.packets_sent}\n")
            self.metrics["attack_stats"] = {
                "attack_type": "dns-reply-flood",
                "start_time": attack_start,
                "end_time": attack_end,
                "duration": attack_end - attack_start,
                "target": f"{self.server_ip}:{self.server_port}",
                "spoofed_ip": self.spoofed_client_ip,
                "threads": self.attack_threads,
                "dns_queries_sent": attack.packets_sent,
            }
            self.results_queue.put(("attack_completed", self.metrics["attack_stats"]))
            logging.warning(
                f"[{thread_name}] DNS Reply Flood attack completed after {attack_end - attack_start:.2f} seconds"
            )
            logging.warning(
                f"[{thread_name}] Attack generated {attack.packets_sent} queries"
            )
        except Exception as e:
            logging.error(f"[{thread_name}] DNS Reply Flood attack failed: {e}")
            self.results_queue.put(("attack_error", str(e)))

    def _dos_monitor_send_query(self, test_domain):
        start_time = time.time()
        query = dns.message.make_query(test_domain, "A")
        try:
            response = dns.query.udp(
                query, self.server_ip, port=self.server_port, timeout=5
            )
            end_time = time.time()
            response_time = (end_time - start_time) * 1000
            if response.rcode() == 0:
                status = "SUCCESS"
            elif response.rcode() == 3:
                status = "NXDOMAIN"
            else:
                status = f"RCODE_{response.rcode()}"
        except Exception as e:
            end_time = time.time()
            response_time = (end_time - start_time) * 1000
            status = f"FAILED: {str(e)}"
        return response_time, status, start_time, end_time

    def _dos_monitor_determine_phase(self, elapsed):
        if elapsed < 15:
            return "baseline"
        elif elapsed < (15 + self.attack_duration):
            return "during_attack"
        else:
            return "post_attack"

    def _dos_monitor_log_and_metrics(
        self, log_file, phase, test_domain, response_time, status
    ):
        log_entry = f"[{datetime.now()}] Phase: {phase:12} | Domain: {test_domain:25} | Response: {response_time:7.2f}ms | Status: {status}\n"
        log_file.write(log_entry)
        log_file.flush()
        self.metrics[phase].append(response_time)
        self.metrics["dos_monitor"].append(
            {
                "timestamp": time.time(),
                "phase": phase,
                "domain": test_domain,
                "response_time_ms": response_time,
                "status": status,
            }
        )

    def _dos_monitor_dos_detection(self, thread_name):
        recent = self.metrics["dos_monitor"][-5:]
        if len(recent) == 5:
            avg_recent = mean([r["response_time_ms"] for r in recent])
            failures = sum(
                1
                for r in recent
                if "FAILED" in r["status"] or "timeout" in r["status"].lower()
            )
            if avg_recent > 1000 or failures >= 2:
                logging.warning(
                    f"[{thread_name}] 🚨 DoS detected: avg={avg_recent:.2f}ms, failures={failures}/5"
                )

    def dos_monitoring_thread(self):
        thread_name = "DoS-Monitor"
        logging.info(f"[{thread_name}] Starting DoS impact monitoring")
        time.sleep(5)
        self.metrics["dos_monitor"] = []
        legit_domain = "www.example.com"
        nonexist_domain = "nonexistent12345.example.com"
        query_toggle = True
        with open(f"{LOGGING_DIR}/dos_monitoring.log", "w") as log_file:
            log_file.write(f"DoS Impact Monitoring started at {datetime.now()}\n")
            log_file.write("Monitoring: Service degradation and attack indicators\n")
            log_file.write("=" * 60 + "\n")
            while not self.stop_event.is_set():
                try:
                    test_domain = legit_domain if query_toggle else nonexist_domain
                    query_toggle = not query_toggle
                    response_time, status, start_time, end_time = (
                        self._dos_monitor_send_query(test_domain)
                    )
                    elapsed = end_time - start_time
                    phase = self._dos_monitor_determine_phase(elapsed)
                    self._dos_monitor_log_and_metrics(
                        log_file, phase, test_domain, response_time, status
                    )
                    self._dos_monitor_dos_detection(thread_name)
                    time.sleep(2)
                except Exception as e:
                    logging.error(f"[{thread_name}] Monitoring error: {e}")
                    time.sleep(1)
        logging.info(f"[{thread_name}] DoS monitoring completed")

    def cleanup(self):
        logging.info("Starting simulation cleanup...")
        self.stop_event.set()
        if self.dns_server_process:
            try:
                self.dns_server_process.terminate()
                self.dns_server_process.wait(timeout=5)
                logging.info("DNS server terminated successfully")
            except Exception as e:
                logging.error(f"Error terminating DNS server: {e}")
                try:
                    self.dns_server_process.kill()
                except Exception:
                    pass
        logging.info("Simulation cleanup completed")

    def run_simulation(self):
        print("\n🚀 Starting DNS Reply Flood Simulation")
        print("=" * 70)
        print(f"Attack Duration: {self.attack_duration}s")
        print(f"Attack Threads: {self.attack_threads}")
        print(f"Target DNS Server: {self.server_ip}:{self.server_port}")
        print(f"Spoofed Client IP: {self.spoofed_client_ip}")
        print("=" * 70)
        try:
            threads = [
                threading.Thread(
                    target=self.start_dns_server_thread, name="Thread-1-DNS-Server"
                ),
                threading.Thread(target=self.client_thread, name="Thread-2-Client"),
                threading.Thread(
                    target=self.dns_reply_flood_attack_thread, name="Thread-3-Attack"
                ),
                threading.Thread(
                    target=self.dos_monitoring_thread, name="Thread-4-DoS-Monitor"
                ),
            ]
            for i, thread in enumerate(threads):
                thread.start()
                logging.info(f"Started {thread.name}")
                time.sleep(2)
            print("\n📍 SIMULATION PHASES:")
            print("Phase 1: Baseline measurement (15 seconds)")
            print(f"Phase 2: DNS Reply Flood Attack ({self.attack_duration} seconds)")
            print("Phase 3: Post-attack (15 seconds)")
            print("=" * 70)
            threads[2].join()
            print("\n🔥 DNS ATTACK PHASE COMPLETED")
            print("🔍 Continuing post-attack monitoring and recovery assessment...")
            post_attack_duration = 15
            for remaining in range(post_attack_duration, 0, -5):
                print(f"⏱️  Post-attack monitoring: {remaining}s remaining...")
                time.sleep(5)
            print("✅ Post-attack monitoring completed")
            self.stop_event.set()
            for i, thread in enumerate(threads):
                if i != 2:
                    thread.join(timeout=10)
                    if thread.is_alive():
                        logging.warning(f"{thread.name} did not stop gracefully")
                    else:
                        logging.info(f"{thread.name} stopped successfully")
            print("\n📊 Generating summary report...")
            self.generate_report()
        except KeyboardInterrupt:
            logging.warning("Simulation interrupted by user")
            self.stop_event.set()
        except Exception as e:
            logging.error(f"Simulation failed: {e}")
            self.stop_event.set()
        finally:
            self.cleanup()

    def generate_report(self):
        print("\n=== DNS REPLY FLOOD SIMULATION REPORT ===")
        if self.metrics["attack_stats"]:
            stats = self.metrics["attack_stats"]
            print(f"Attack Type: {stats.get('attack_type')}")
            print(f"DNS Queries Sent: {stats.get('dns_queries_sent', 0)}")
            print(f"Attack Duration: {stats.get('duration', 0):.2f} seconds")
            print(f"Attack Threads: {stats.get('threads', 0)}")
            print(f"Target Server: {stats.get('target', 'Unknown')}")
            print(f"Spoofed IP: {stats.get('spoofed_ip', 'Unknown')}")
        # Phase-wise response times and degradation
        for phase in ["baseline", "during_attack", "post_attack"]:
            phase_times = [
                r["response_time_ms"]
                for r in self.metrics["client_requests"]
                if r["phase"].lower() == phase and r["status"] == "SUCCESS"
            ]
            if phase_times:
                avg = mean(phase_times)
                degraded = [t for t in phase_times if t > 1000]
                degradation_percent = (
                    (len(degraded) / len(phase_times) * 100) if phase_times else 0
                )
                print(
                    f"{phase.title()} Avg Response Time: {avg:.2f} ms | Service Degradation (>1s): {degradation_percent:.2f}%"
                )
            else:
                print(
                    f"{phase.title()} Avg Response Time: N/A | Service Degradation (>1s): N/A"
                )
        # Compute client metrics
        client_success = sum(
            1 for r in self.metrics["client_requests"] if r["status"] == "SUCCESS"
        )
        client_fail = sum(
            1 for r in self.metrics["client_requests"] if r["status"] == "FAILED"
        )
        total_client = client_success + client_fail
        success_rate = (client_success / total_client * 100) if total_client > 0 else 0
        print(f"Client Success: {client_success}, Client Failures: {client_fail}")
        print(f"Client Success Rate: {success_rate:.2f}%")
        print("=== END OF REPORT ===\n")


def setup_signal_handler(simulation, threads):
    def signal_handler(sig, frame):
        logging.info("Received interrupt signal")
        simulation.stop_event.set()
        for thread in threads:
            if thread.is_alive():
                thread.join(timeout=10)
        simulation.cleanup()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)


def start_simulation_threads(simulation):
    threads = [
        threading.Thread(
            target=simulation.start_dns_server_thread, name="Thread-1-DNS-Server"
        ),
        threading.Thread(target=simulation.client_thread, name="Thread-2-Client"),
        threading.Thread(
            target=simulation.dns_reply_flood_attack_thread, name="Thread-3-Attack"
        ),
        threading.Thread(
            target=simulation.dos_monitoring_thread, name="Thread-4-DoS-Monitor"
        ),
    ]
    for i, thread in enumerate(threads):
        thread.start()
        logging.info(f"Started {thread.name}")
        time.sleep(2)
    return threads


def _join_threads(threads, skip_index=None):
    for i, thread in enumerate(threads):
        if skip_index is not None and i == skip_index:
            continue
        thread.join(timeout=10)
        if thread.is_alive():
            logging.warning(f"{thread.name} did not stop gracefully")
        else:
            logging.info(f"{thread.name} stopped successfully")

def _handle_cleanup(simulation, threads):
    simulation.stop_event.set()
    _join_threads(threads)
    simulation.cleanup()

def run_simulation_and_report(simulation, threads):
    try:
        print("\n📍 SIMULATION PHASES:")
        print("Phase 1: Baseline measurement (15 seconds)")
        print(f"Phase 2: DNS Reply Flood Attack ({simulation.attack_duration} seconds)")
        print("Phase 3: Post-attack (15 seconds)")
        print("=" * 70)
        threads[2].join()
        print("\n🔥 DNS ATTACK PHASE COMPLETED")
        print("🔍 Continuing post-attack monitoring and recovery assessment...")
        post_attack_duration = 15
        for remaining in range(post_attack_duration, 0, -5):
            print(f"⏱️  Post-attack monitoring: {remaining}s remaining...")
            time.sleep(5)
        print("✅ Post-attack monitoring completed")
        simulation.stop_event.set()
        _join_threads(threads, skip_index=2)
        print("\n📊 Generating summary report...")
        simulation.generate_report()
    except KeyboardInterrupt:
        logging.warning("Simulation interrupted by user")
        _handle_cleanup(simulation, threads)
    except Exception as e:
        logging.error(f"Simulation failed: {e}")
        _handle_cleanup(simulation, threads)
    finally:
        simulation.cleanup()


def main():
    parser = argparse.ArgumentParser(
        description="DNS Reply Flood Attack Simulation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
DNS Reply Flood Attack Simulation

Network Topology:
  Target DNS Server    : Victim DNS server (port 5353)
  Legitimate Client    : Normal user (whose IP is spoofed by attacker)
  Attacker             : DNSReplyFlood (spoofs client IP)
  DoS Monitor          : Monitors service degradation

Phases:
  1. Baseline (15s)
  2. Attack (duration)
  3. Post-attack (15s)

Examples:
  sudo python dns_reply_flood_simulation.py --duration 30 --threads 10
        """,
    )
    parser.add_argument(
        "--duration",
        "-d",
        type=int,
        default=30,
        help="Attack duration in seconds (default: 30)",
    )
    parser.add_argument(
        "--threads",
        "-t",
        type=int,
        default=10,
        help="Number of attack threads (default: 10)",
    )
    parser.add_argument(
        "--server-port",
        type=int,
        default=5353,
        help="Target DNS server port (default: 5353)",
    )
    parser.add_argument(
        "--server-ip",
        type=str,
        default="127.0.0.1",
        help="DNS server IP address (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--spoofed-client-ip",
        type=str,
        default="192.168.1.200",
        help="Client IP to spoof (default: 192.168.1.200)",
    )
    parser.add_argument(
        "--spoofed-client-port",
        type=int,
        default=12345,
        help="Client port to spoof (default: 12345)",
    )
    args = parser.parse_args()
    simulation = DNSReplyFloodSimulation(
        attack_duration=args.duration,
        attack_threads=args.threads,
        server_port=args.server_port,
        server_ip=args.server_ip,
        spoofed_client_ip=args.spoofed_client_ip,
        spoofed_client_port=args.spoofed_client_port,
    )

    threads = start_simulation_threads(simulation)
    setup_signal_handler(simulation, threads)
    run_simulation_and_report(simulation, threads)


if __name__ == "__main__":
    main()
