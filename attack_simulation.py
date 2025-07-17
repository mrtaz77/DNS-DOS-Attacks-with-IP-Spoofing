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
import json
import argparse

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(threadName)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("attack_simulation.log"), logging.StreamHandler()],
)


class AttackSimulation:
    def __init__(
        self,
        attack_duration=60,
        attack_threads=25,
        server_port=5353,
        server_ip="127.0.0.1",
        attack_type="udp-fragment",
    ):
        self.dns_server_process = None
        self.stop_event = threading.Event()
        self.results_queue = queue.Queue()
        self.server_port = server_port
        self.server_ip = server_ip
        self.attack_duration = attack_duration
        self.attack_threads = attack_threads
        self.attack_type = attack_type

        self.metrics = {
            "baseline": [],
            "during_attack": [],
            "post_attack": [],
            "client_requests": [],
            "attack_stats": {},
        }

        os.makedirs("logs", exist_ok=True)

    def dns_server_thread(self):
        """Thread 1: Run DNS server with logging"""
        thread_name = "DNS-Server"
        logging.info(f"[{thread_name}] Starting DNS server on port {self.server_port}")

        try:
            # Start DNS server with detailed logging
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
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                bufsize=1,
            )

            # Log DNS server output in real-time
            with open("logs/dns_server.log", "w") as log_file:
                log_file.write(f"DNS Server started at {datetime.now()}\n")
                log_file.write("=" * 50 + "\n")

                while (
                    not self.stop_event.is_set()
                    and self.dns_server_process.poll() is None
                ):
                    try:
                        output = self.dns_server_process.stdout.readline()
                        if output:
                            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                            log_entry = f"[{timestamp}] {output.strip()}\n"
                            log_file.write(log_entry)
                            log_file.flush()
                            logging.debug(f"[{thread_name}] {output.strip()}")
                    except Exception as e:
                        logging.error(
                            f"[{thread_name}] Error reading server output: {e}"
                        )
                        break

            logging.info(f"[{thread_name}] DNS server thread completed")

        except Exception as e:
            logging.error(f"[{thread_name}] Failed to start DNS server: {e}")
            self.results_queue.put(("dns_server_error", str(e)))

    def normal_client_thread(self):
        """Thread 2: Normal client making regular DNS requests"""
        thread_name = "Normal-Client"
        logging.info(f"[{thread_name}] Starting normal client requests")

        # Wait for DNS server to start
        time.sleep(3)

        request_count = 0
        successful_requests = 0
        failed_requests = 0
        response_times = []

        with open("logs/client_requests.log", "w") as log_file:
            log_file.write(f"Normal Client started at {datetime.now()}\n")
            log_file.write("=" * 50 + "\n")

            while not self.stop_event.is_set():
                try:
                    start_time = time.time()

                    # Create DNS query
                    query_name = f"test{request_count % 10}.example.com"
                    query = dns.message.make_query(query_name, "A")

                    # Send query with timeout
                    dns.query.udp(
                        query, self.server_ip, port=self.server_port, timeout=5
                    )

                    end_time = time.time()
                    response_time = (end_time - start_time) * 1000  # Convert to ms

                    successful_requests += 1
                    response_times.append(response_time)

                    log_entry = f"[{datetime.now()}] Query {request_count}: {query_name} -> {response_time:.2f}ms (SUCCESS)\n"
                    log_file.write(log_entry)
                    log_file.flush()

                    # Store metrics
                    self.metrics["client_requests"].append(
                        {
                            "timestamp": time.time(),
                            "query": query_name,
                            "response_time_ms": response_time,
                            "status": "success",
                        }
                    )

                    logging.debug(
                        f"[{thread_name}] Query {request_count}: {response_time:.2f}ms"
                    )

                except Exception as e:
                    failed_requests += 1
                    log_entry = (
                        f"[{datetime.now()}] Query {request_count}: FAILED - {str(e)}\n"
                    )
                    log_file.write(log_entry)
                    log_file.flush()

                    # Store failed request
                    self.metrics["client_requests"].append(
                        {
                            "timestamp": time.time(),
                            "query": f"test{request_count % 10}.example.com",
                            "response_time_ms": 0,
                            "status": "failed",
                            "error": str(e),
                        }
                    )

                    logging.warning(
                        f"[{thread_name}] Query {request_count} failed: {e}"
                    )

                request_count += 1
                time.sleep(2)  # Request every 2 seconds

        # Final statistics
        total_requests = successful_requests + failed_requests
        success_rate = (
            (successful_requests / total_requests * 100) if total_requests > 0 else 0
        )
        avg_response_time = mean(response_times) if response_times else 0

        stats = {
            "total_requests": total_requests,
            "successful": successful_requests,
            "failed": failed_requests,
            "success_rate": success_rate,
            "avg_response_time_ms": avg_response_time,
        }

        self.results_queue.put(("client_stats", stats))
        logging.info(f"[{thread_name}] Completed: {stats}")

    def attack_thread(self):
        """Thread 3: UDP Attack (Fragment or Fraggle based on type)"""
        thread_name = "UDP-Attack"
        logging.info(f"[{thread_name}] Preparing {self.attack_type} attack")

        # Wait for baseline measurement
        time.sleep(15)

        logging.warning(
            f"[{thread_name}] 🚨 LAUNCHING {self.attack_type.upper()} ATTACK!"
        )

        try:
            # Import and configure attack based on type
            sys.path.append(".")

            if self.attack_type == "udp-fragment":
                from attack.udp_fragmented_flood import FragmentedUDPFlood

                min_packet_size = int("Minimum packet size: ")
                max_packet_size = int("Maximum packet size: ")

                attack = FragmentedUDPFlood(
                    target_ip=self.server_ip,
                    target_port=self.server_port,
                    duration=self.attack_duration,
                    threads=self.attack_threads,
                    min_packet_size=min_packet_size,
                    max_packet_size=max_packet_size
                )
            elif self.attack_type == "udp-fraggle":
                from attack.udp_fraggle import UDPFraggle

                # For fraggle attack, target_ip is the victim, server_ip is where responses go
                attack = UDPFraggle(
                    target_ip=self.server_ip,  # Victim IP (our DNS server)
                    target_port=self.server_port,
                    duration=self.attack_duration,
                    threads=self.attack_threads,
                )
            else:
                raise ValueError(f"Unknown attack type: {self.attack_type}")

            # Log attack start
            with open("logs/attack.log", "w") as log_file:
                log_file.write(
                    f"{self.attack_type.upper()} Attack started at {datetime.now()}\n"
                )
                log_file.write("=" * 50 + "\n")
                log_file.write(f"Attack Type: {self.attack_type}\n")
                log_file.write(f"Target: {self.server_ip}:{self.server_port}\n")
                log_file.write(f"Duration: {self.attack_duration} seconds\n")
                log_file.write(f"Threads: {self.attack_threads}\n")
                log_file.write("=" * 50 + "\n")

            # Execute attack
            attack_start = time.time()
            attack.attack()
            attack_end = time.time()

            # Log attack completion
            with open("logs/attack.log", "a") as log_file:
                log_file.write(f"\nAttack completed at {datetime.now()}\n")
                log_file.write(
                    f"Actual duration: {attack_end - attack_start:.2f} seconds\n"
                )
                log_file.write(f"Packets sent: {attack.packets_sent}\n")

            attack_stats = {
                "attack_type": self.attack_type,
                "start_time": attack_start,
                "end_time": attack_end,
                "duration": attack_end - attack_start,
                "target": f"{self.server_ip}:{self.server_port}",
                "threads": self.attack_threads,
                "packets_sent": attack.packets_sent,
            }

            self.metrics["attack_stats"] = attack_stats
            self.results_queue.put(("attack_completed", attack_stats))

            logging.warning(
                f"[{thread_name}] {self.attack_type.upper()} attack completed after {attack_end - attack_start:.2f} seconds"
            )

        except Exception as e:
            logging.error(
                f"[{thread_name}] {self.attack_type.upper()} attack failed: {e}"
            )
            self.results_queue.put(("attack_error", str(e)))

    def monitor_thread(self):
        """Thread 4: Monitor DNS server metrics for DoS indicators"""
        thread_name = "DoS-Monitor"
        logging.info(f"[{thread_name}] Starting DNS server monitoring")

        # Wait for DNS server to start
        time.sleep(3)

        phase = "baseline"
        attack_detected_time = None

        with open("logs/monitoring.log", "w") as log_file:
            self._write_monitoring_header(log_file)

            while not self.stop_event.is_set():
                try:
                    response_time, status = self._perform_dns_query()
                    current_time = time.time()

                    phase, attack_detected_time = self._update_monitoring_phase(
                        phase,
                        current_time,
                        attack_detected_time,
                        response_time,
                        status,
                        thread_name,
                    )

                    self._log_monitoring_data(log_file, phase, response_time, status)
                    self._store_metric_data(phase, current_time, response_time, status)
                    self._check_dos_conditions(phase, thread_name)

                    time.sleep(1)

                except Exception as e:
                    logging.error(f"[{thread_name}] Monitoring error: {e}")
                    time.sleep(1)

        logging.info(f"[{thread_name}] Monitoring completed")

    def _write_monitoring_header(self, log_file):
        """Write header to monitoring log file"""
        log_file.write(f"DNS DoS Monitoring started at {datetime.now()}\n")
        log_file.write("=" * 50 + "\n")

    def _perform_dns_query(self):
        """Perform DNS query and measure response time"""
        start_time = time.time()
        query = dns.message.make_query("monitor.example.com", "A")

        try:
            dns.query.udp(query, self.server_ip, port=self.server_port, timeout=3)
            end_time = time.time()
            response_time = (end_time - start_time) * 1000
            status = "SUCCESS"
        except Exception as e:
            end_time = time.time()
            response_time = (end_time - start_time) * 1000
            status = f"FAILED: {str(e)}"

        return response_time, status

    def _update_monitoring_phase(
        self,
        phase,
        current_time,
        attack_detected_time,
        response_time,
        status,
        thread_name,
    ):
        """Update monitoring phase based on current conditions"""
        if self._should_detect_attack(phase, current_time, response_time, status):
            if attack_detected_time is None:
                attack_detected_time = current_time
                phase = "during_attack"
                logging.warning(f"[{thread_name}] 🚨 DoS ATTACK DETECTED!")
        elif self._should_enter_post_attack_phase(
            phase, current_time, attack_detected_time
        ):
            phase = "post_attack"
            logging.info(f"[{thread_name}] Post-attack monitoring phase")

        return phase, attack_detected_time

    def _should_detect_attack(self, phase, current_time, response_time, status):
        """Check if attack conditions are met"""
        return (
            phase == "baseline"
            and current_time > (time.time() - 45)
            and (response_time > 100 or "FAILED" in status)
        )

    def _should_enter_post_attack_phase(
        self, phase, current_time, attack_detected_time
    ):
        """Check if should enter post-attack phase"""
        return (
            phase == "during_attack"
            and attack_detected_time
            and (current_time - attack_detected_time) > 35
        )

    def _log_monitoring_data(self, log_file, phase, response_time, status):
        """Log monitoring data to file"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        log_entry = f"[{timestamp}] Phase: {phase:12} | Response: {response_time:7.2f}ms | Status: {status}\n"
        log_file.write(log_entry)
        log_file.flush()

    def _store_metric_data(self, phase, current_time, response_time, status):
        """Store metric data based on current phase"""
        metric_data = {
            "timestamp": current_time,
            "phase": phase,
            "response_time_ms": response_time,
            "status": status,
        }

        self.metrics[phase].append(metric_data)

    def _check_dos_conditions(self, phase, thread_name):
        """Check for DoS conditions in recent metrics"""
        if len(self.metrics[phase]) < 3:
            return

        recent_metrics = self.metrics[phase][-3:]
        recent_times = [m["response_time_ms"] for m in recent_metrics]
        recent_failures = sum(1 for m in recent_metrics if "FAILED" in m["status"])

        avg_recent = mean(recent_times)

        if (
            self._dos_conditions_met(avg_recent, recent_failures)
            and phase != "during_attack"
        ):
            logging.warning(
                f"[{thread_name}] 🚨 DoS conditions detected: {avg_recent:.2f}ms avg, {recent_failures}/3 failures"
            )

    def _dos_conditions_met(self, avg_recent, recent_failures):
        """Check if DoS conditions are met"""
        return avg_recent > 200 or recent_failures >= 2

    def _analyze_baseline_performance(self):
        """Analyze baseline performance metrics"""
        if not self.metrics["baseline"]:
            return {}

        baseline_times = [m["response_time_ms"] for m in self.metrics["baseline"]]
        baseline_failures = sum(
            1 for m in self.metrics["baseline"] if "FAILED" in m["status"]
        )

        return {
            "avg_response_time_ms": round(mean(baseline_times), 2),
            "max_response_time_ms": round(max(baseline_times), 2),
            "min_response_time_ms": round(min(baseline_times), 2),
            "failure_rate_percent": round(
                (baseline_failures / len(self.metrics["baseline"])) * 100, 2
            ),
            "sample_count": len(self.metrics["baseline"]),
        }

    def _analyze_attack_impact(self):
        """Analyze attack impact metrics"""
        if not self.metrics["during_attack"]:
            return {}

        attack_times = [m["response_time_ms"] for m in self.metrics["during_attack"]]
        attack_failures = sum(
            1 for m in self.metrics["during_attack"] if "FAILED" in m["status"]
        )

        attack_data = {
            "avg_response_time_ms": round(mean(attack_times), 2),
            "max_response_time_ms": round(max(attack_times), 2),
            "failure_rate_percent": round(
                (attack_failures / len(self.metrics["during_attack"])) * 100, 2
            ),
            "sample_count": len(self.metrics["during_attack"]),
        }

        # Calculate performance degradation
        if self.metrics["baseline"]:
            baseline_avg = mean(
                [m["response_time_ms"] for m in self.metrics["baseline"]]
            )
            attack_avg = mean(attack_times)
            attack_data["performance_degradation_percent"] = round(
                ((attack_avg - baseline_avg) / baseline_avg) * 100, 2
            )

        return attack_data

    def _analyze_recovery(self):
        """Analyze recovery metrics"""
        if not self.metrics["post_attack"]:
            return {}

        recovery_times = [m["response_time_ms"] for m in self.metrics["post_attack"]]
        recovery_failures = sum(
            1 for m in self.metrics["post_attack"] if "FAILED" in m["status"]
        )

        return {
            "avg_response_time_ms": round(mean(recovery_times), 2),
            "failure_rate_percent": round(
                (recovery_failures / len(self.metrics["post_attack"])) * 100, 2
            ),
            "sample_count": len(self.metrics["post_attack"]),
        }

    def _analyze_client_impact(self):
        """Analyze client impact metrics"""
        if not self.metrics["client_requests"]:
            return {}

        successful_clients = [
            r for r in self.metrics["client_requests"] if r["status"] == "success"
        ]
        failed_clients = [
            r for r in self.metrics["client_requests"] if r["status"] == "failed"
        ]

        return {
            "total_requests": len(self.metrics["client_requests"]),
            "successful_requests": len(successful_clients),
            "failed_requests": len(failed_clients),
            "success_rate_percent": round(
                (len(successful_clients) / len(self.metrics["client_requests"])) * 100,
                2,
            ),
            "avg_response_time_ms": (
                round(mean([r["response_time_ms"] for r in successful_clients]), 2)
                if successful_clients
                else 0
            ),
        }

    def _analyze_dos_indicators(self):
        """Analyze DoS indicators"""
        dos_data = {
            "attack_detected": len(self.metrics["during_attack"]) > 0,
            "max_response_degradation": 0,
            "service_disruption_detected": False,
        }

        if self.metrics["baseline"] and self.metrics["during_attack"]:
            baseline_avg = mean(
                [m["response_time_ms"] for m in self.metrics["baseline"]]
            )
            attack_max = max(
                [m["response_time_ms"] for m in self.metrics["during_attack"]]
            )

            degradation = ((attack_max - baseline_avg) / baseline_avg) * 100
            dos_data["max_response_degradation"] = round(degradation, 2)
            dos_data["service_disruption_detected"] = (
                degradation > 200
            )  # 200% degradation threshold

        return dos_data

    def _print_report_summary(self, report):
        """Print report summary to console"""
        print("\n" + "=" * 80)
        print(f"🎯 UDP {self.attack_type.upper()} ATTACK SIMULATION REPORT")
        print("=" * 80)

        # Attack type specific information
        if self.attack_type == "udp-fragment":
            print("📦 ATTACK METHOD: IP Fragmentation Flood")
            print("   - Large UDP packets fragmented at IP layer")
            print("   - Forces target to consume resources reassembling fragments")
        elif self.attack_type == "udp-fraggle":
            print("📡 ATTACK METHOD: UDP Broadcast Amplification")
            print("   - Spoofed UDP packets sent to broadcast addresses")
            print("   - Network devices respond to victim, amplifying traffic")

        if "attack_type" in self.metrics["attack_stats"]:
            print(f"   - Attack Type: {self.metrics['attack_stats']['attack_type']}")
        if "packets_sent" in self.metrics["attack_stats"]:
            print(f"   - Total Packets Sent: {self.metrics['attack_stats']['packets_sent']}")

        if report["baseline_performance"]:
            print("\n📊 BASELINE PERFORMANCE:")
            print(
                f"   Average Response Time: {report['baseline_performance']['avg_response_time_ms']}ms"
            )
            print(
                f"   Failure Rate: {report['baseline_performance']['failure_rate_percent']}%"
            )

        if report["attack_impact"]:
            print(f"\n🚨 {self.attack_type.upper()} ATTACK IMPACT:")
            print(
                f"   Average Response Time: {report['attack_impact']['avg_response_time_ms']}ms"
            )
            print(
                f"   Failure Rate: {report['attack_impact']['failure_rate_percent']}%"
            )
            if "performance_degradation_percent" in report["attack_impact"]:
                print(
                    f"   Performance Degradation: {report['attack_impact']['performance_degradation_percent']}%"
                )

        if report["client_impact"]:
            print("\n👥 CLIENT IMPACT:")
            print(
                f"   Success Rate: {report['client_impact']['success_rate_percent']}%"
            )
            print(f"   Failed Requests: {report['client_impact']['failed_requests']}")

        print("\n🔍 DoS DETECTION:")
        print(
            f"   Attack Detected: {'✅ YES' if report['dos_indicators']['attack_detected'] else '❌ NO'}"
        )
        print(
            f"   Service Disruption: {'✅ YES' if report['dos_indicators']['service_disruption_detected'] else '❌ NO'}"
        )
        print(
            f"   Max Degradation: {report['dos_indicators']['max_response_degradation']}%"
        )

        print("\n📁 All logs saved in: logs/ directory")
        print("=" * 80)

    def generate_comprehensive_report(self):
        """Generate comprehensive attack simulation report"""
        logging.info("Generating comprehensive simulation report...")

        report = {
            "simulation_summary": {
                "timestamp": datetime.now().isoformat(),
                "server": f"{self.server_ip}:{self.server_port}",
                "total_duration": len(self.metrics["baseline"])
                + len(self.metrics["during_attack"])
                + len(self.metrics["post_attack"]),
            },
            "baseline_performance": self._analyze_baseline_performance(),
            "attack_impact": self._analyze_attack_impact(),
            "recovery_analysis": self._analyze_recovery(),
            "client_impact": self._analyze_client_impact(),
            "dos_indicators": self._analyze_dos_indicators(),
        }

        # Save report
        with open("logs/simulation_report.json", "w") as f:
            json.dump(report, f, indent=2)

        # Print summary
        self._print_report_summary(report)

        return report

    def cleanup(self):
        """Clean up resources"""
        logging.info("Starting cleanup...")

        # Signal all threads to stop
        self.stop_event.set()

        # Terminate DNS server
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

        logging.info("Cleanup completed")

    def run_simulation(self):
        """Run the complete 4-thread attack simulation"""
        print("🚀 Starting 4-Thread UDP Attack Simulation")
        print("=" * 80)
        print("Thread 1: DNS Server with logging")
        print("Thread 2: Normal client requests")
        print(f"Thread 3: {self.attack_type.upper()} attack")
        print("Thread 4: DoS monitoring and metrics")
        print("=" * 80)
        print(f"Attack Type: {self.attack_type}")
        print(
            f"Attack Parameters: Duration={self.attack_duration}s, Threads={self.attack_threads}"
        )
        print(f"Target Server: {self.server_ip}:{self.server_port}")
        print("=" * 80)

        try:
            # Create and start all 4 threads
            threads = [
                threading.Thread(
                    target=self.dns_server_thread, name="Thread-1-DNS-Server"
                ),
                threading.Thread(
                    target=self.normal_client_thread, name="Thread-2-Normal-Client"
                ),
                threading.Thread(
                    target=self.attack_thread,
                    name=f"Thread-3-{self.attack_type.upper()}-Attack",
                ),
                threading.Thread(
                    target=self.monitor_thread, name="Thread-4-DoS-Monitor"
                ),
            ]

            # Start all threads
            for thread in threads:
                thread.start()
                logging.info(f"Started {thread.name}")
                time.sleep(1)  # Stagger thread starts

            logging.info("All threads started successfully")

            # Wait for attack thread to complete (this determines simulation end)
            threads[2].join()  # Wait for attack thread
            logging.info("Attack thread completed")

            # Allow some time for post-attack monitoring
            time.sleep(10)

            # Signal stop and wait for other threads
            self.stop_event.set()

            for i, thread in enumerate(threads):
                if i != 2:  # Skip attack thread (already completed)
                    thread.join(timeout=10)
                    if thread.is_alive():
                        logging.warning(f"{thread.name} did not stop gracefully")

            # Generate comprehensive report
            self.generate_comprehensive_report()

        except KeyboardInterrupt:
            logging.warning("Simulation interrupted by user")
            self.stop_event.set()

        except Exception as e:
            logging.error(f"Simulation failed: {e}")
            self.stop_event.set()

        finally:
            self.cleanup()


def main():
    parser = argparse.ArgumentParser(
        description="UDP Attack Simulation (Fragment or Fraggle)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Attack Types:
  udp-fragment : UDP Fragmented Flood attack using IP fragmentation
  udp-fraggle  : UDP Fraggle attack using broadcast amplification

Examples:
  sudo python attack_simulation.py --attack-type udp-fragment --duration 30 --threads 10
  sudo python attack_simulation.py --attack-type udp-fraggle --duration 60 --threads 20
  sudo python attack_simulation.py --attack-type udp-fragment --target-ip 192.168.1.100 --target-port 53
        """,
    )

    parser.add_argument(
        "--attack-type",
        choices=["udp-fragment", "udp-fraggle"],
        default="udp-fragment",
        help="Type of UDP attack to perform (default: udp-fragment)",
    )

    parser.add_argument(
        "--duration",
        "-d",
        type=int,
        default=60,
        help="Attack duration in seconds (default: 60)",
    )

    parser.add_argument(
        "--threads",
        "-t",
        type=int,
        default=25,
        help="Number of attack threads (default: 25)",
    )

    parser.add_argument(
        "--target-ip",
        type=str,
        default="127.0.0.1",
        help="Target DNS server IP address (default: 127.0.0.1)",
    )

    parser.add_argument(
        "--target-port",
        type=int,
        default=5353,
        help="Target DNS server port (default: 5353)",
    )

    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable verbose logging"
    )

    args = parser.parse_args()

    # Validate arguments
    if args.duration <= 0:
        print("Error: Duration must be positive")
        sys.exit(1)

    if args.threads <= 0 or args.threads > 100:
        print("Error: Threads must be between 1 and 100")
        sys.exit(1)

    if args.target_port <= 0 or args.target_port > 65535:
        print("Error: Port must be between 1 and 65535")
        sys.exit(1)

    # Set logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    print(f"🎯 UDP {args.attack_type.upper()} Attack Simulation")
    print(f"Attack Type: {args.attack_type}")
    print(f"Target: {args.target_ip}:{args.target_port}")
    print(f"Duration: {args.duration} seconds")
    print(f"Threads: {args.threads}")
    print(f"Verbose: {args.verbose}")
    print()

    # Attack-specific warnings
    if args.attack_type == "udp-fraggle":
        print("⚠️  WARNING: UDP Fraggle attack uses broadcast amplification!")
        print("⚠️  This may affect network devices beyond the target!")
        print("⚠️  Ensure you have permission to test on the entire network segment!")
        print()

    # Confirm before starting
    try:
        confirm = input("Start the attack simulation? (yes/no): ").lower().strip()
        if confirm != "yes":
            print("Attack simulation cancelled.")
            sys.exit(0)
    except KeyboardInterrupt:
        print("\nAttack simulation cancelled.")
        sys.exit(0)

    simulation = AttackSimulation(
        attack_duration=args.duration,
        attack_threads=args.threads,
        server_port=args.target_port,
        server_ip=args.target_ip,
        attack_type=args.attack_type,
    )

    # Handle Ctrl+C gracefully
    def signal_handler(sig, frame):
        logging.info("Received interrupt signal")
        simulation.stop_event.set()
        simulation.cleanup()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    # Run the simulation
    simulation.run_simulation()


if __name__ == "__main__":
    main()
