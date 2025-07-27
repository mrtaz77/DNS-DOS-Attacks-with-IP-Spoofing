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
import random
import string

LOGGING_DIR = "dns-random-subdomain"

class DNSSubdomainFloodSimulation:
    """
    DNS Random Subdomain Query Flood Attack Simulation

    Network Topology:
    1. ATTACKER: Generates random subdomain queries with IP spoofing
    2. TARGET DNS SERVER: Primary victim (resolver/recursive server)
    3. LEGITIMATE DNS CLIENTS: Collateral victims experiencing service degradation

    Attack Flow\t- Attacker floods target with random subdomain queries (abc123.example.com\t- Target server performs recursive lookups to external DNS (8.8.8.8\t- External servers respond with NXDOMAIN for non-existent subdomain\t- Processing overhead overwhelms target serve\t- Legitimate clients experience slow/failed DNS resolution
    """

    def __init__(
        self,
        attack_duration=60,
        attack_threads=15,
        target_server_port=5353,
        server_ip="127.0.0.1",
    ):
        self.target_dns_process = None
        self.stop_event = threading.Event()
        self.results_queue = queue.Queue()

        # Network configuration
        self.server_ip = server_ip
        self.target_server_port = target_server_port  # Target DNS resolver

        # Attack configuration
        self.attack_duration = attack_duration
        self.attack_threads = attack_threads

        # Simulation metrics
        self.metrics = {
            "baseline": [],
            "during_attack": [],
            "post_attack": [],
            "client_requests": [],
            "attack_stats": {},
        }

        # DNS domains for testing
        self.legitimate_domains = [
            "www.example.com",
            "ns1.example.com",
            "www.facebook.com",
            "www.github.com",
            "www.youtube.com",
            "www.leetcode.com"
        ]

        self.base_domains = ["example.com", "google.com", "test.com"]

        os.makedirs(f"{LOGGING_DIR}", exist_ok=True)

        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - %(threadName)s - %(levelname)s - %(message)s",
            handlers=[
                logging.FileHandler(f"{LOGGING_DIR}/dns_subdomain_flood_simulation.log"),
                logging.StreamHandler(),
            ],
        )

    def target_dns_server_thread(self):
        """Thread 1: Target DNS Server (Recursive Resolver) - Primary Victim"""
        thread_name = "Target-DNS-Server"
        logging.info(
            f"[{thread_name}] Starting TARGET DNS server on port {self.target_server_port}"
        )

        try:
            # Start target DNS server with forwarding to Google DNS
            # This simulates a corporate/ISP DNS resolver
            self.target_dns_process = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "dns_server.main",
                    "--zone",
                    "dns_server/zones/primary.zone",
                    "--addr",
                    self.server_ip,
                    "--port-udp",
                    str(self.target_server_port),
                    "--port-tcp",
                    str(self.target_server_port + 1),
                    "--forwarder",
                    "8.8.8.8",  # Forward to Google DNS
                    "--rate-limit-threshold",
                    "100",  # Some protection
                    "--rate-limit-window",
                    "10",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                bufsize=1,
            )

            # Log target DNS server output
            with open(f"{LOGGING_DIR}/target_dns_server.log", "w") as log_file:
                log_file.write(
                    f"TARGET DNS Server (Victim) started at {datetime.now()}\n"
                )
                log_file.write("Role: Recursive resolver receiving attack traffic\n")
                log_file.write("Forwarder: 8.8.8.8 (Google DNS)\n")
                log_file.write("=" * 60 + "\n")

                while (
                    not self.stop_event.is_set()
                    and self.target_dns_process.poll() is None
                ):
                    try:
                        output = self.target_dns_process.stdout.readline()
                        if output:
                            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                            log_entry = f"[{timestamp}] {output.strip()}\n"
                            log_file.write(log_entry)
                            log_file.flush()

                            # Log high-load indicators
                            if any(
                                keyword in output.lower()
                                for keyword in [
                                    "error",
                                    "timeout",
                                    "failed",
                                    "nxdomain",
                                    "rate limit",
                                ]
                            ):
                                logging.warning(f"[{thread_name}] {output.strip()}")
                            else:
                                logging.debug(f"[{thread_name}] {output.strip()}")
                    except Exception as e:
                        logging.error(
                            f"[{thread_name}] Error reading server output: {e}"
                        )
                        break

            logging.info(f"[{thread_name}] Target DNS server thread completed")

        except Exception as e:
            logging.error(f"[{thread_name}] Failed to start target DNS server: {e}")
            self.results_queue.put(("target_dns_error", str(e)))

    def _determine_client_phase(self, elapsed_time):
        if elapsed_time < 15:
            return "BASELINE"
        elif elapsed_time < (15 + self.attack_duration):
            return "UNDER_ATTACK"
        else:
            return "POST_ATTACK_RECOVERY"

    def _send_dns_query_and_time(self, query_name):
        query = dns.message.make_query(query_name, "A")
        start_time = time.time()
        dns.query.udp(query, self.server_ip, port=self.target_server_port, timeout=8)
        end_time = time.time()
        return (end_time - start_time) * 1000  # ms

    def _log_and_store_client_metrics(
        self,
        log_file,
        request_count,
        query_name,
        response_time,
        status,
        client_phase,
        error=None,
    ):
        timestamp = datetime.now()
        if error:
            log_entry = f"[{timestamp}] [{client_phase}] Query {request_count}: {query_name} FAILED - {error}\n"
        else:
            log_entry = f"[{timestamp}] [{client_phase}] Query {request_count}: {query_name} -> {response_time:.2f}ms ({status})\n"
        log_file.write(log_entry)
        log_file.flush()
        metric = {
            "timestamp": time.time(),
            "query": query_name,
            "response_time_ms": response_time if not error else 0,
            "status": status if not error else "FAILED",
            "degraded": (response_time > 1000) if not error else True,
            "phase": client_phase,
        }
        if error:
            metric["error"] = str(error)
        self.metrics["client_requests"].append(metric)

    def _get_status_from_response_time(self, response_time):
        if response_time > 2000:
            return "SUCCESS_VERY_SLOW"
        elif response_time > 1000:
            return "SUCCESS_SLOW"
        else:
            return "SUCCESS"

    def _log_slow_and_recovery(
        self, thread_name, client_phase, query_name, response_time
    ):
        if response_time > 1000:
            logging.warning(
                f"[{thread_name}] [{client_phase}] SLOW RESPONSE: {query_name} -> {response_time:.2f}ms"
            )
        else:
            logging.debug(
                f"[{thread_name}] [{client_phase}] Query: {query_name} -> {response_time:.2f}ms"
            )
        if client_phase == "POST_ATTACK_RECOVERY" and response_time < 500:
            logging.info(
                f"[{thread_name}] 🔄 SERVICE RECOVERY: {query_name} -> {response_time:.2f}ms (Normal response time restored)"
            )

    def legitimate_client_thread(self):
        """Thread 2: Legitimate DNS Client - Collateral Victim"""
        thread_name = "Legitimate-Client"
        logging.info(f"[{thread_name}] Starting legitimate client requests")

        time.sleep(5)
        request_count = 0
        successful_requests = 0
        failed_requests = 0
        response_times = []
        phase_start_time = time.time()

        with open(f"{LOGGING_DIR}/legitimate_client.log", "w") as log_file:
            log_file.write(f"Legitimate DNS Client started at {datetime.now()}\n")
            log_file.write(
                "Role: Normal user experiencing service degradation during attack\n"
            )
            log_file.write(
                "Queries: Legitimate domains (www.example.com, mail.example.com, etc.)\n"
            )
            log_file.write("=" * 70 + "\n")

            while not self.stop_event.is_set():
                query_name = self.legitimate_domains[
                    request_count % len(self.legitimate_domains)
                ]
                elapsed = time.time() - phase_start_time
                client_phase = self._determine_client_phase(elapsed)
                try:
                    response_time = self._send_dns_query_and_time(query_name)
                    successful_requests += 1
                    response_times.append(response_time)
                    status = self._get_status_from_response_time(response_time)
                    self._log_and_store_client_metrics(
                        log_file,
                        request_count,
                        query_name,
                        response_time,
                        status,
                        client_phase,
                    )
                    self._log_slow_and_recovery(
                        thread_name, client_phase, query_name, response_time
                    )
                except Exception as e:
                    failed_requests += 1
                    self._log_and_store_client_metrics(
                        log_file,
                        request_count,
                        query_name,
                        0,
                        "FAILED",
                        client_phase,
                        error=str(e),
                    )
                    logging.error(
                        f"[{thread_name}] [{client_phase}] Query {request_count} FAILED: {e}"
                    )
                request_count += 1
                time.sleep(2)

        total_requests = successful_requests + failed_requests
        success_rate = (
            (successful_requests / total_requests * 100) if total_requests > 0 else 0
        )
        avg_response_time = mean(response_times) if response_times else 0
        degraded_requests = len(
            [r for r in self.metrics["client_requests"] if r.get("degraded", False)]
        )
        post_attack_requests = [
            r
            for r in self.metrics["client_requests"]
            if r.get("phase") == "POST_ATTACK_RECOVERY"
        ]
        recovery_success = len(
            [
                r
                for r in post_attack_requests
                if r["status"] in ["SUCCESS"] and r["response_time_ms"] < 500
            ]
        )
        stats = {
            "total_requests": total_requests,
            "successful": successful_requests,
            "failed": failed_requests,
            "success_rate": success_rate,
            "avg_response_time_ms": avg_response_time,
            "degraded_requests": degraded_requests,
            "degradation_rate": (
                (degraded_requests / total_requests * 100) if total_requests > 0 else 0
            ),
            "post_attack_requests": len(post_attack_requests),
            "recovery_success_count": recovery_success,
            "service_recovery_rate": (
                (recovery_success / len(post_attack_requests) * 100)
                if post_attack_requests
                else 0
            ),
        }
        self.results_queue.put(("client_stats", stats))
        logging.info(f"[{thread_name}] Final client impact analysis: {stats}")

    def dns_subdomain_flood_attack_thread(self):
        """Thread 3: DNS Random Subdomain Query Flood Attack - The Attacker"""
        thread_name = "DNS-Subdomain-Attack"
        logging.info(
            f"[{thread_name}] Preparing DNS Random Subdomain Query Flood attack"
        )

        # Wait for baseline measurement
        time.sleep(15)

        logging.warning(
            f"[{thread_name}] 🚨 LAUNCHING DNS RANDOM SUBDOMAIN QUERY FLOOD ATTACK!"
        )

        try:
            # Import and configure DNS subdomain flood attack
            sys.path.append(".")
            from attack.dns_random_subdomain_query_flood import (
                DNSRandomSubdomainQueryFlood,
            )

            attack = DNSRandomSubdomainQueryFlood(
                target_ip=self.server_ip,
                target_port=self.target_server_port,  # Attack the target DNS server
                duration=self.attack_duration,
                threads=self.attack_threads,
                base_domains=self.base_domains,  # Use various domains
                query_types=[1, 28, 15, 5, 2, 16],  # Multiple query types
            )

            # Log attack start
            with open(f"{LOGGING_DIR}/attack.log", "w") as log_file:
                log_file.write(
                    f"DNS Random Subdomain Query Flood Attack started at {datetime.now()}\n"
                )
                log_file.write("=" * 70 + "\n")
                log_file.write("Attack Type: DNS Random Subdomain Query Flood\n")
                log_file.write(
                    f"Target: {self.server_ip}:{self.target_server_port} (Target DNS Server)\n"
                )
                log_file.write("External Forwarder: 8.8.8.8 (Google DNS)\n")
                log_file.write(f"Duration: {self.attack_duration} seconds\n")
                log_file.write(f"Threads: {self.attack_threads}\n")
                log_file.write(f"Base Domains: {self.base_domains}\n")
                log_file.write("Attack Mechanism:\n")
                log_file.write("  1. Generate random subdomains (abc123.example.com)\n")
                log_file.write("  2. Spoof source IP addresses\n")
                log_file.write("  3. Flood target DNS server with queries\n")
                log_file.write("  4. Target forwards to 8.8.8.8\n")
                log_file.write("  5. External servers respond with NXDOMAIN\n")
                log_file.write("  6. Processing overhead overwhelms target\n")
                log_file.write("=" * 70 + "\n")

            # Execute attack
            attack_start = time.time()
            attack.attack()
            attack_end = time.time()

            # Log attack completion
            with open(f"{LOGGING_DIR}/attack.log", "a") as log_file:
                log_file.write(
                    f"\nDNS Subdomain Flood attack completed at {datetime.now()}\n"
                )
                log_file.write(
                    f"Actual duration: {attack_end - attack_start:.2f} seconds\n"
                )
                log_file.write(f"DNS queries sent: {attack.packets_sent}\n")
                log_file.write(
                    f"Estimated NXDOMAIN responses generated: {attack.packets_sent}\n"
                )
                log_file.write("Target server processing load: SEVERE\n")
                log_file.write(
                    "External DNS server impact: HIGH (NXDOMAIN generation)\n"
                )

            attack_stats = {
                "attack_type": "dns-random-subdomain-flood",
                "start_time": attack_start,
                "end_time": attack_end,
                "duration": attack_end - attack_start,
                "target": f"{self.server_ip}:{self.target_server_port}",
                "external_forwarder": "8.8.8.8",
                "threads": self.attack_threads,
                "dns_queries_sent": attack.packets_sent,
                "base_domains": self.base_domains,
                "estimated_nxdomain_responses": attack.packets_sent,
            }

            self.metrics["attack_stats"] = attack_stats
            self.results_queue.put(("attack_completed", attack_stats))

            logging.warning(
                f"[{thread_name}] DNS Subdomain Flood attack completed after {attack_end - attack_start:.2f} seconds"
            )
            logging.warning(
                f"[{thread_name}] Attack generated {attack.packets_sent} random subdomain queries"
            )

        except Exception as e:
            logging.error(f"[{thread_name}] DNS Subdomain Flood attack failed: {e}")
            self.results_queue.put(("attack_error", str(e)))

    def dos_monitoring_thread(self):
        """Thread 4: DoS Impact Monitoring - Attack Effect Analysis"""
        thread_name = "DoS-Monitor"
        logging.info(f"[{thread_name}] Starting DNS DoS impact monitoring")

        # Wait for DNS servers to start
        time.sleep(5)

        phase = "baseline"
        attack_detected_time = None
        query_count = 0

        with open(f"{LOGGING_DIR}/dos_monitoring.log", "w") as log_file:
            log_file.write(f"DNS DoS Impact Monitoring started at {datetime.now()}\n")
            log_file.write("Monitoring: Service degradation and attack indicators\n")
            log_file.write("Focus: Response times, failure rates, NXDOMAIN patterns\n")
            log_file.write("=" * 70 + "\n")

            while not self.stop_event.is_set():
                try:
                    # Test both legitimate and random subdomains
                    if query_count % 2 == 0:
                        # Test legitimate domain
                        test_domain = "www.example.com"
                        expected_result = "SUCCESS"
                    else:
                        # Test random subdomain (should get NXDOMAIN)
                        random_subdomain = "".join(
                            random.choice(string.ascii_lowercase) for _ in range(8)
                        )
                        test_domain = f"{random_subdomain}.example.com"
                        expected_result = "NXDOMAIN"

                    response_time, status = self._perform_monitoring_query(test_domain)
                    current_time = time.time()

                    # Update monitoring phase
                    phase, attack_detected_time = self._update_monitoring_phase(
                        phase,
                        current_time,
                        attack_detected_time,
                        response_time,
                        status,
                        thread_name,
                    )

                    # Log monitoring data
                    log_entry = (
                        f"[{datetime.now()}] Phase: {phase:12} | "
                        f"Domain: {test_domain:25} | "
                        f"Response: {response_time:7.2f}ms | "
                        f"Status: {status} | "
                        f"Expected: {expected_result}\n"
                    )
                    log_file.write(log_entry)
                    log_file.flush()

                    # Store metric data
                    self._store_monitoring_data(
                        phase, current_time, response_time, status, test_domain
                    )

                    # Check for DoS conditions
                    self._check_dns_dos_conditions(phase, thread_name)

                    query_count += 1
                    time.sleep(1.5)

                except Exception as e:
                    logging.error(f"[{thread_name}] Monitoring error: {e}")
                    time.sleep(1)

        logging.info(f"[{thread_name}] DoS monitoring completed")

    def _perform_monitoring_query(self, domain):
        """Perform DNS monitoring query and measure response time"""
        start_time = time.time()
        query = dns.message.make_query(domain, "A")

        try:
            response = dns.query.udp(
                query, self.server_ip, port=self.target_server_port, timeout=5
            )
            end_time = time.time()
            response_time = (end_time - start_time) * 1000

            # Check response code
            if response.rcode() == dns.rcode.NXDOMAIN:
                status = "NXDOMAIN"
            elif response.rcode() == dns.rcode.NOERROR:
                status = "SUCCESS"
            else:
                status = f"RCODE_{response.rcode()}"

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
        # Detect attack based on response time degradation or failure patterns
        if phase == "baseline" and (
            response_time > 500 or "FAILED" in status or "timeout" in status.lower()
        ):

            if attack_detected_time is None:
                attack_detected_time = current_time
                phase = "during_attack"
                logging.warning(
                    f"[{thread_name}] 🚨 DNS DoS ATTACK DETECTED! Response degradation observed"
                )

        elif (
            phase == "during_attack"
            and attack_detected_time
            and (current_time - attack_detected_time) > (self.attack_duration + 10)
        ):
            phase = "post_attack"
            logging.info(f"[{thread_name}] Entering post-attack recovery monitoring")

        return phase, attack_detected_time

    def _store_monitoring_data(
        self, phase, current_time, response_time, status, domain
    ):
        """Store monitoring data based on current phase"""
        metric_data = {
            "timestamp": current_time,
            "phase": phase,
            "response_time_ms": response_time,
            "status": status,
            "domain": domain,
            "is_random_subdomain": len(domain.split(".")[0]) == 8
            and domain.split(".")[0].islower(),
        }

        self.metrics[phase].append(metric_data)

    def _check_dns_dos_conditions(self, phase, thread_name):
        """Check for DNS DoS conditions in recent metrics"""
        if len(self.metrics[phase]) < 5:
            return

        recent_metrics = self.metrics[phase][-5:]
        recent_times = [m["response_time_ms"] for m in recent_metrics]
        recent_failures = sum(1 for m in recent_metrics if "FAILED" in m["status"])
        recent_timeouts = sum(
            1 for m in recent_metrics if "timeout" in m["status"].lower()
        )

        avg_recent = mean(recent_times)

        # DNS-specific DoS indicators
        dns_dos_conditions = (
            avg_recent > 1000  # Average response time > 1 second
            or recent_failures >= 2  # 2+ failures in last 5 queries
            or recent_timeouts >= 2  # 2+ timeouts in last 5 queries
            or max(recent_times) > 3000  # Any response > 3 seconds
        )

        if dns_dos_conditions and phase != "during_attack":
            logging.warning(
                f"[{thread_name}] 🚨 DNS DoS conditions detected: "
                f"avg={avg_recent:.2f}ms, failures={recent_failures}/5, timeouts={recent_timeouts}/5"
            )

    def _analyze_baseline_performance(self):
        """Analyze baseline DNS performance metrics"""
        if not self.metrics["baseline"]:
            return {}

        baseline_times = [m["response_time_ms"] for m in self.metrics["baseline"]]
        baseline_failures = sum(
            1 for m in self.metrics["baseline"] if "FAILED" in m["status"]
        )
        baseline_nxdomains = sum(
            1 for m in self.metrics["baseline"] if m["status"] == "NXDOMAIN"
        )

        return {
            "avg_response_time_ms": round(mean(baseline_times), 2),
            "max_response_time_ms": round(max(baseline_times), 2),
            "min_response_time_ms": round(min(baseline_times), 2),
            "failure_rate_percent": round(
                (baseline_failures / len(self.metrics["baseline"])) * 100, 2
            ),
            "nxdomain_rate_percent": round(
                (baseline_nxdomains / len(self.metrics["baseline"])) * 100, 2
            ),
            "sample_count": len(self.metrics["baseline"]),
        }

    def _analyze_attack_impact(self):
        """Analyze DNS attack impact metrics"""
        if not self.metrics["during_attack"]:
            return {}

        attack_times = [m["response_time_ms"] for m in self.metrics["during_attack"]]
        attack_failures = sum(
            1 for m in self.metrics["during_attack"] if "FAILED" in m["status"]
        )
        attack_nxdomains = sum(
            1 for m in self.metrics["during_attack"] if m["status"] == "NXDOMAIN"
        )
        attack_timeouts = sum(
            1 for m in self.metrics["during_attack"] if "timeout" in m["status"].lower()
        )

        attack_data = {
            "avg_response_time_ms": round(mean(attack_times), 2),
            "max_response_time_ms": round(max(attack_times), 2),
            "failure_rate_percent": round(
                (attack_failures / len(self.metrics["during_attack"])) * 100, 2
            ),
            "nxdomain_rate_percent": round(
                (attack_nxdomains / len(self.metrics["during_attack"])) * 100, 2
            ),
            "timeout_rate_percent": round(
                (attack_timeouts / len(self.metrics["during_attack"])) * 100, 2
            ),
            "sample_count": len(self.metrics["during_attack"]),
        }

        # Calculate performance degradation as a ratio
        if self.metrics["baseline"]:
            baseline_avg = mean(
                [m["response_time_ms"] for m in self.metrics["baseline"]]
            )
            attack_avg = mean(attack_times)
            if baseline_avg > 0:
                attack_data["performance_degradation_ratio"] = round(
                    attack_avg / baseline_avg, 2
                )
            else:
                attack_data["performance_degradation_ratio"] = None

        return attack_data

    def _analyze_client_impact(self):
        """Analyze legitimate client impact metrics"""
        if not self.metrics["client_requests"]:
            return {}

        successful_clients = [
            r
            for r in self.metrics["client_requests"]
            if r["status"] in ["SUCCESS", "SUCCESS_SLOW", "SUCCESS_VERY_SLOW"]
        ]
        failed_clients = [
            r for r in self.metrics["client_requests"] if r["status"] == "FAILED"
        ]
        degraded_clients = [
            r for r in self.metrics["client_requests"] if r.get("degraded", False)
        ]

        return {
            "total_requests": len(self.metrics["client_requests"]),
            "successful_requests": len(successful_clients),
            "failed_requests": len(failed_clients),
            "degraded_requests": len(degraded_clients),
            "success_rate_percent": round(
                (len(successful_clients) / len(self.metrics["client_requests"])) * 100,
                2,
            ),
            "degradation_rate_percent": round(
                (len(degraded_clients) / len(self.metrics["client_requests"])) * 100, 2
            ),
            "avg_response_time_ms": (
                round(mean([r["response_time_ms"] for r in successful_clients]), 2)
                if successful_clients
                else 0
            ),
        }

    def _analyze_dns_dos_indicators(self):
        """Analyze DNS-specific DoS indicators"""
        dos_data = {
            "attack_detected": len(self.metrics["during_attack"]) > 0,
            "max_response_time_ratio": 0,
            "service_disruption_detected": False,
        }

        if self.metrics["baseline"] and self.metrics["during_attack"]:
            baseline_avg = mean(
                [m["response_time_ms"] for m in self.metrics["baseline"]]
            )
            attack_max = max(
                [m["response_time_ms"] for m in self.metrics["during_attack"]]
            )

            if baseline_avg > 0:
                ratio = attack_max / baseline_avg
                dos_data["max_response_time_ratio"] = round(ratio, 2)
                dos_data["service_disruption_detected"] = (
                    ratio > 4.0  # 4x degradation threshold
                )
            else:
                dos_data["max_response_time_ratio"] = None
                dos_data["service_disruption_detected"] = False

        return dos_data

    def _print_dns_report_summary(self, report):
        """Print DNS-specific report summary to console"""
        print("\n" + "=" * 90)
        print("🎯 DNS RANDOM SUBDOMAIN QUERY FLOOD ATTACK SIMULATION REPORT")
        print("=" * 90)
        print("📦 ATTACK METHOD: DNS Random Subdomain Query Flood")
        print("\t- Random subdomain queries (abc123.example.com, xyz789.test.com)")
        print("\t- IP spoofing for distributed appearance")
        print("\t- Forces cache misses and recursive lookups")
        print("\t- Overwhelms DNS resolver processing capacity")
        print("\t- Generates NXDOMAIN responses from external DNS (8.8.8.8)")

        if "attack_stats" in self.metrics:
            stats = self.metrics["attack_stats"]
            print("\n🔥 ATTACK STATISTICS:")
            print(f"\tDNS Queries Sent: {stats.get('dns_queries_sent', 0)}")
            print(f"\tAttack Duration: {stats.get('duration', 0):.2f} seconds")
            print(f"\tAttack Threads: {stats.get('threads', 0)}")
            print(f"\tTarget Server: {stats.get('target', 'Unknown')}")
            print(
                f"\tExternal Forwarder: {stats.get('external_forwarder', 'Unknown')}"
            )

        if report["baseline_performance"]:
            baseline = report["baseline_performance"]
            print("\n📊 BASELINE DNS PERFORMANCE:")
            print(f"\tAverage Response Time: {baseline['avg_response_time_ms']}ms")
            print(f"\tNXDOMAIN Rate: {baseline['nxdomain_rate_percent']}%")
            print(f"\tFailure Rate: {baseline['failure_rate_percent']}%")

        if report["attack_impact"]:
            impact = report["attack_impact"]
            print("\n🚨 DNS ATTACK IMPACT:")
            print(f"\tAverage Response Time: {impact['avg_response_time_ms']}ms")
            print(f"\tMax Response Time: {impact['max_response_time_ms']}ms")
            print(f"\tFailure Rate: {impact['failure_rate_percent']}%")
            print(f"\tTimeout Rate: {impact['timeout_rate_percent']}%")
            if "performance_degradation_ratio" in impact:
                ratio = impact["performance_degradation_ratio"]
                if ratio is not None:
                    print(f"\tPerformance Degradation: {ratio}x slower than baseline")
                else:
                    print("\tPerformance Degradation: N/A")

        if report["client_impact"]:
            client = report["client_impact"]
            print("\n👥 LEGITIMATE CLIENT IMPACT:")
            print(f"\tSuccess Rate: {client['success_rate_percent']}%")
            print(f"\tService Degradation: {client['degradation_rate_percent']}%")
            print(f"\tFailed Requests: {client['failed_requests']}")
            print(f"\tAverage Response Time: {client['avg_response_time_ms']}ms")

        print("\n🔍 DNS DoS DETECTION:")
        dos = report["dns_dos_indicators"]
        print(f"\tAttack Detected: {'✅ YES' if dos['attack_detected'] else '❌ NO'}")
        print(
            f"\tService Disruption: {'✅ YES' if dos['service_disruption_detected'] else '❌ NO'}"
        )
        if dos["max_response_time_ratio"] is not None:
            print(f"\tMax Degradation: {dos['max_response_time_ratio']}x slower than baseline")
        else:
            print("\tMax Degradation: N/A")
        print("=" * 90)

    def generate_comprehensive_report(self):
        """Generate comprehensive DNS attack simulation report"""
        logging.info("Generating comprehensive DNS attack simulation report...")

        report = {
            "simulation_summary": {
                "timestamp": datetime.now().isoformat(),
                "attack_type": "dns-random-subdomain-flood",
                "target_server": f"{self.server_ip}:{self.target_server_port}",
                "external_forwarder": "8.8.8.8",
                "total_duration": self.attack_duration
                + 30,  # Including baseline and recovery
                "network_topology": {
                    "attacker": "DNS Random Subdomain Query Flood",
                    "target": "Recursive DNS Resolver",
                    "external": "Google DNS (8.8.8.8)",
                    "clients": "Normal DNS users",
                },
            },
            "baseline_performance": self._analyze_baseline_performance(),
            "attack_impact": self._analyze_attack_impact(),
            "client_impact": self._analyze_client_impact(),
            "dns_dos_indicators": self._analyze_dns_dos_indicators(),
        }

        # Save detailed report
        with open(f"{LOGGING_DIR}/dns_simulation_report.json", "w") as f:
            json.dump(report, f, indent=2)

        # Print summary
        self._print_dns_report_summary(report)

        return report

    def cleanup(self):
        """Clean up DNS server processes and resources"""
        logging.info("Starting DNS simulation cleanup...")

        # Signal all threads to stop
        self.stop_event.set()

        # Terminate target DNS server
        if self.target_dns_process:
            try:
                self.target_dns_process.terminate()
                self.target_dns_process.wait(timeout=5)
                logging.info("Target DNS server terminated successfully")
            except Exception as e:
                logging.error(f"Error terminating target DNS server: {e}")
                try:
                    self.target_dns_process.kill()
                except Exception:
                    pass

        logging.info("DNS simulation cleanup completed")

    def run_simulation(self):
        """Run the complete 4-thread DNS subdomain flood attack simulation"""
        print("🚀 Starting 4-Thread DNS Random Subdomain Query Flood Simulation")
        print("=" * 90)
        print("Network Topology:")
        print("Thread 1: Target DNS Server (Recursive Resolver) - PRIMARY VICTIM")
        print("Thread 2: Legitimate DNS Client - Collateral victim")
        print("Thread 3: DNS Subdomain Flood Attack - THE ATTACKER")
        print("Thread 4: DoS Impact Monitoring - Attack detection")
        print("=" * 90)
        print("Attack Type: DNS Random Subdomain Query Flood")
        print(f"Attack Duration: {self.attack_duration}s")
        print(f"Attack Threads: {self.attack_threads}")
        print(f"Target DNS Server: {self.server_ip}:{self.target_server_port}")
        print("External Forwarder: 8.8.8.8 (Google DNS)")
        print(f"Base Domains: {', '.join(self.base_domains)}")
        print("=" * 90)

        try:
            # Create and start all 4 threads
            threads = [
                threading.Thread(
                    target=self.target_dns_server_thread, name="Thread-1-Target-DNS"
                ),
                threading.Thread(
                    target=self.legitimate_client_thread, name="Thread-2-Legit-Client"
                ),
                threading.Thread(
                    target=self.dns_subdomain_flood_attack_thread,
                    name="Thread-3-DNS-Attack",
                ),
                threading.Thread(
                    target=self.dos_monitoring_thread, name="Thread-4-DoS-Monitor"
                ),
            ]

            # Start all threads with staggered timing
            for i, thread in enumerate(threads):
                thread.start()
                logging.info(f"Started {thread.name}")
                time.sleep(2)  # Stagger thread starts more for DNS servers

            logging.info("All threads started successfully - DNS simulation running")

            # Show phases of simulation
            print("\n📍 SIMULATION PHASES:")
            print("Phase 1: Baseline measurement (15 seconds)")
            print(
                f"Phase 2: DNS Subdomain Flood Attack ({self.attack_duration} seconds)"
            )
            print("Phase 3: Post-attack recovery monitoring (30 seconds)")
            print("=" * 90)

            # Wait for attack thread to complete (determines simulation end)
            threads[2].join()  # Wait for DNS attack thread
            logging.info("DNS subdomain flood attack thread completed")
            print("\n🔥 DNS ATTACK PHASE COMPLETED")
            print("🔍 Continuing post-attack monitoring and recovery assessment...")

            # Extended post-attack monitoring period (30 seconds)
            post_attack_duration = 30
            logging.info(
                f"Starting {post_attack_duration}s post-attack monitoring period"
            )

            for remaining in range(post_attack_duration, 0, -5):
                print(f"⏱️  Post-attack monitoring: {remaining}s remaining...")
                time.sleep(5)

            print("✅ Post-attack monitoring completed")

            # Signal stop and wait for other threads
            self.stop_event.set()
            logging.info("Signaling all threads to stop gracefully")

            # Wait for threads to complete gracefully with longer timeout
            for i, thread in enumerate(threads):
                if i != 2:  # Skip attack thread (already completed)
                    thread.join(timeout=20)  # Increased timeout for graceful shutdown
                    if thread.is_alive():
                        logging.warning(f"{thread.name} did not stop gracefully")
                    else:
                        logging.info(f"{thread.name} stopped successfully")

            print("\n📊 Generating comprehensive attack report...")
            # Generate comprehensive DNS attack report
            self.generate_comprehensive_report()

        except KeyboardInterrupt:
            logging.warning("DNS simulation interrupted by user")
            self.stop_event.set()

        except Exception as e:
            logging.error(f"DNS simulation failed: {e}")
            self.stop_event.set()

        finally:
            self.cleanup()


def main():
    parser = argparse.ArgumentParser(
        description="DNS Random Subdomain Query Flood Attack Simulation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
DNS Random Subdomain Query Flood Attack Simulation

Network Topology:
  Target DNS Server    : Recursive resolver receiving attack traffic (port 5353)
  External Forwarder   : Google DNS (8.8.8.8) for upstream queries
  Legitimate Client    : Normal user experiencing service degradation
  Attacker            : Generates random subdomain queries with IP spoofing
  
Attack Mechanism:
  1. Attacker generates random subdomains (abc123.example.com)
  2. Spoofs source IP addresses to appear distributed
  3. Floods target DNS server with queries
  4. Target forwards to external DNS (8.8.8.8)
  5. External servers respond with NXDOMAIN for non-existent subdomains
  6. Processing overhead overwhelms target server
  7. Legitimate clients experience slow/failed DNS resolution

Examples:
  sudo python dns_random_subdomain_attack_simulation.py --duration 30 --threads 10
  sudo python dns_random_subdomain_attack_simulation.py --target-port 5353
        """,
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
        default=15,
        help="Number of attack threads (default: 15)",
    )

    parser.add_argument(
        "--target-port",
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
        "--verbose", "-v", action="store_true", help="Enable verbose logging"
    )

    args = parser.parse_args()

    # Validate arguments
    if args.duration <= 0:
        print("Error: Duration must be positive")
        sys.exit(1)

    if args.threads <= 0 or args.threads > 50:
        print("Error: Threads must be between 1 and 50")
        sys.exit(1)

    if args.target_port <= 0 or args.target_port > 65535:
        print("Error: Target port must be between 1 and 65535")
        sys.exit(1)

    # Set logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    print("🎯 DNS Random Subdomain Query Flood Attack Simulation")
    print(f"Attack Duration: {args.duration} seconds")
    print(f"Attack Threads: {args.threads}")
    print(f"Target DNS Server: {args.server_ip}:{args.target_port}")
    print("External Forwarder: 8.8.8.8 (Google DNS)")
    print(f"Verbose Logging: {args.verbose}")
    print()

    # Confirm before starting
    try:
        confirm = input("Start the DNS attack simulation? (yes/no): ").lower().strip()
        if confirm != "yes":
            print("DNS attack simulation cancelled.")
            sys.exit(0)
    except KeyboardInterrupt:
        print("\nDNS attack simulation cancelled.")
        sys.exit(0)

    simulation = DNSSubdomainFloodSimulation(
        attack_duration=args.duration,
        attack_threads=args.threads,
        target_server_port=args.target_port,
        server_ip=args.server_ip,
    )

    # Handle Ctrl+C gracefully
    def signal_handler(sig, frame):
        logging.info("Received interrupt signal")
        simulation.stop_event.set()
        simulation.cleanup()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    # Run the DNS attack simulation
    simulation.run_simulation()


if __name__ == "__main__":
    main()
