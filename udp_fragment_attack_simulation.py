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
    handlers=[logging.FileHandler("udp_fragment_attack_simulation.log"), logging.StreamHandler()],
)


class UDPFragmentFloodSimulation:
    """
    UDP Fragmented Flood Attack Simulation
    
    This simulation demonstrates the impact of UDP fragmentation attacks on DNS servers.
    The attack sends large UDP packets that are fragmented at the IP layer, forcing
    the target to consume resources reassembling fragments.
    
    4-Thread Architecture:
    1. DNS Server Thread: Target victim server
    2. Normal Client Thread: Legitimate DNS requests
    3. UDP Fragment Attack Thread: The attacker
    4. DoS Monitoring Thread: Impact measurement
    """
    
    def __init__(
        self,
        attack_duration=60,
        attack_threads=25,
        server_port=5353,
        server_ip="127.0.0.1",
        min_packet_size=1500,
        max_packet_size=8000,
    ):
        self.dns_server_process = None
        self.stop_event = threading.Event()
        self.results_queue = queue.Queue()
        self.server_port = server_port
        self.server_ip = server_ip
        self.attack_duration = attack_duration
        self.attack_threads = attack_threads
        self.min_packet_size = min_packet_size
        self.max_packet_size = max_packet_size

        self.metrics = {
            "baseline": [],
            "during_attack": [],
            "post_attack": [],
            "client_requests": [],
            "fragment_attack_stats": {},
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

            # Log DNS server output with fragment-specific monitoring
            with open("logs/dns_server_fragment_attack.log", "w") as log_file:
                log_file.write(f"DNS Server (UDP Fragment Attack Target) started at {datetime.now()}\n")
                log_file.write("Expected Impact: Memory exhaustion from fragment reassembly\n")
                log_file.write("Monitoring: Fragment timeouts, reassembly failures, resource usage\n")
                log_file.write("=" * 70 + "\n")

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
                            
                            # Monitor for fragment-related issues
                            if any(keyword in output.lower() for keyword in 
                                  ['fragment', 'reassembl', 'timeout', 'memory', 'buffer']):
                                logging.warning(f"[{thread_name}] FRAGMENT IMPACT: {output.strip()}")
                            else:
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
        """Thread 2: Normal Client - Experiences Service Degradation"""
        thread_name = "Normal-Client"
        logging.info(f"[{thread_name}] Starting normal DNS client requests")

        # Wait for DNS server to start
        time.sleep(3)

        request_count = 0
        successful_requests = 0
        failed_requests = 0
        response_times = []

        with open("logs/client_requests_during_fragment_attack.log", "w") as log_file:
            log_file.write(f"Normal DNS Client started at {datetime.now()}\n")
            log_file.write("Role: Legitimate user experiencing UDP fragment attack impact\n")
            log_file.write("Expected: Slow responses due to server resource exhaustion\n")
            log_file.write("=" * 70 + "\n")

            while not self.stop_event.is_set():
                try:
                    start_time = time.time()

                    # Create DNS query for legitimate domain
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

                    # Determine if response is slow (impact of fragment attack)
                    status = "SUCCESS"
                    if response_time > 500:
                        status = "SUCCESS_SLOW"
                    elif response_time > 1000:
                        status = "SUCCESS_VERY_SLOW"

                    log_entry = f"[{datetime.now()}] Query {request_count}: {query_name} -> {response_time:.2f}ms ({status})\n"
                    log_file.write(log_entry)
                    log_file.flush()

                    # Store metrics
                    self.metrics["client_requests"].append(
                        {
                            "timestamp": time.time(),
                            "query": query_name,
                            "response_time_ms": response_time,
                            "status": status,
                            "degraded": response_time > 500
                        }
                    )

                    if response_time > 500:
                        logging.warning(f"[{thread_name}] SLOW RESPONSE: {query_name} -> {response_time:.2f}ms")
                    else:
                        logging.debug(f"[{thread_name}] Query {request_count}: {response_time:.2f}ms")

                except Exception as e:
                    failed_requests += 1
                    log_entry = (
                        f"[{datetime.now()}] Query {request_count}: {query_name} FAILED - {str(e)}\n"
                    )
                    log_file.write(log_entry)
                    log_file.flush()

                    # Store failed request
                    self.metrics["client_requests"].append(
                        {
                            "timestamp": time.time(),
                            "query": query_name,
                            "response_time_ms": 0,
                            "status": "FAILED",
                            "error": str(e),
                            "degraded": True
                        }
                    )

                    logging.error(f"[{thread_name}] Query {request_count} FAILED: {e}")

                request_count += 1
                time.sleep(2)  # Request every 2 seconds

        # Calculate final statistics
        total_requests = successful_requests + failed_requests
        success_rate = (
            (successful_requests / total_requests * 100) if total_requests > 0 else 0
        )
        avg_response_time = mean(response_times) if response_times else 0
        degraded_requests = len([r for r in self.metrics["client_requests"] if r.get("degraded", False)])

        stats = {
            "total_requests": total_requests,
            "successful": successful_requests,
            "failed": failed_requests,
            "success_rate": success_rate,
            "avg_response_time_ms": avg_response_time,
            "degraded_requests": degraded_requests,
            "degradation_rate": (degraded_requests / total_requests * 100) if total_requests > 0 else 0
        }

        self.results_queue.put(("client_stats", stats))
        logging.info(f"[{thread_name}] Fragment attack impact on client: {stats}")

    def udp_fragment_attack_thread(self):
        """Thread 3: UDP Fragmented Flood Attack - The Attacker"""
        thread_name = "UDP-Fragment-Attack"
        logging.info(f"[{thread_name}] Preparing UDP Fragmented Flood attack")

        # Wait for baseline measurement
        time.sleep(15)

        logging.warning(f"[{thread_name}] 🚨 LAUNCHING UDP FRAGMENTED FLOOD ATTACK!")

        try:
            # Import UDP fragment attack
            sys.path.append(".")
            from attack.udp_fragmented_flood import FragmentedUDPFlood

            attack = FragmentedUDPFlood(
                target_ip=self.server_ip,
                target_port=self.server_port,
                duration=self.attack_duration,
                threads=self.attack_threads,
                min_packet_size=self.min_packet_size,
                max_packet_size=self.max_packet_size,
            )

            # Log attack start
            with open("logs/udp_fragment_attack.log", "w") as log_file:
                log_file.write(f"UDP Fragmented Flood Attack started at {datetime.now()}\n")
                log_file.write("=" * 70 + "\n")
                log_file.write("Attack Type: UDP Fragmented Flood\n")
                log_file.write(f"Target: {self.server_ip}:{self.server_port}\n")
                log_file.write(f"Duration: {self.attack_duration} seconds\n")
                log_file.write(f"Threads: {self.attack_threads}\n")
                log_file.write(f"Packet Size Range: {self.min_packet_size}-{self.max_packet_size} bytes\n")
                log_file.write("Attack Mechanism:\n")
                log_file.write("  1. Generate large UDP packets (>MTU)\n")
                log_file.write("  2. IP layer fragments packets automatically\n")
                log_file.write("  3. Send fragments out of order\n")
                log_file.write("  4. Force target to consume memory for reassembly\n")
                log_file.write("  5. Overwhelm fragment reassembly buffers\n")
                log_file.write("=" * 70 + "\n")

            # Execute attack
            attack_start = time.time()
            attack.attack()
            attack_end = time.time()

            # Log attack completion
            with open("logs/udp_fragment_attack.log", "a") as log_file:
                log_file.write(f"\nUDP Fragment attack completed at {datetime.now()}\n")
                log_file.write(f"Actual duration: {attack_end - attack_start:.2f} seconds\n")
                log_file.write(f"Fragment packets sent: {attack.packets_sent}\n")
                log_file.write(f"Estimated fragments generated: {attack.packets_sent * 3}\n")  # Approx 3 fragments per packet
                log_file.write("Target memory pressure: SEVERE\n")
                log_file.write("Fragment reassembly impact: HIGH\n")

            fragment_attack_stats = {
                "attack_type": "udp-fragmented-flood",
                "start_time": attack_start,
                "end_time": attack_end,
                "duration": attack_end - attack_start,
                "target": f"{self.server_ip}:{self.server_port}",
                "threads": self.attack_threads,
                "packets_sent": attack.packets_sent,
                "min_packet_size": self.min_packet_size,
                "max_packet_size": self.max_packet_size,
                "estimated_fragments": attack.packets_sent * 3,
                "fragment_overhead_bytes": attack.packets_sent * 60  # IP header overhead per fragment
            }

            self.metrics["fragment_attack_stats"] = fragment_attack_stats
            self.results_queue.put(("attack_completed", fragment_attack_stats))

            logging.warning(
                f"[{thread_name}] UDP Fragment attack completed after {attack_end - attack_start:.2f} seconds"
            )
            logging.warning(
                f"[{thread_name}] Sent {attack.packets_sent} fragmented packets, estimated {attack.packets_sent * 3} fragments"
            )

        except Exception as e:
            logging.error(f"[{thread_name}] UDP Fragment attack failed: {e}")
            self.results_queue.put(("attack_error", str(e)))

    def fragment_dos_monitor_thread(self):
        """Thread 4: Fragment-Specific DoS Monitoring"""
        thread_name = "Fragment-DoS-Monitor"
        logging.info(f"[{thread_name}] Starting UDP fragment DoS impact monitoring")

        # Wait for DNS server to start
        time.sleep(3)

        phase = "baseline"
        attack_detected_time = None

        with open("logs/fragment_dos_monitoring.log", "w") as log_file:
            log_file.write(f"UDP Fragment DoS Monitoring started at {datetime.now()}\n")
            log_file.write("Monitoring: Fragment reassembly impact on DNS service\n")
            log_file.write("Indicators: Response delays, timeouts, memory pressure\n")
            log_file.write("=" * 70 + "\n")

            while not self.stop_event.is_set():
                try:
                    response_time, status = self._perform_fragment_monitoring_query()
                    current_time = time.time()

                    # Update monitoring phase based on fragment attack indicators
                    phase, attack_detected_time = self._update_fragment_monitoring_phase(
                        phase,
                        current_time,
                        attack_detected_time,
                        response_time,
                        status,
                        thread_name,
                    )

                    # Log monitoring data
                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
                    log_entry = (f"[{timestamp}] Phase: {phase:12} | "
                               f"Response: {response_time:7.2f}ms | "
                               f"Status: {status}\n")
                    log_file.write(log_entry)
                    log_file.flush()

                    # Store metric data
                    self._store_fragment_metric_data(phase, current_time, response_time, status)

                    # Check for fragment-specific DoS conditions
                    self._check_fragment_dos_conditions(phase, thread_name)

                    time.sleep(1)

                except Exception as e:
                    logging.error(f"[{thread_name}] Fragment monitoring error: {e}")
                    time.sleep(1)

        logging.info(f"[{thread_name}] Fragment DoS monitoring completed")

    def _perform_fragment_monitoring_query(self):
        """Perform DNS query to monitor fragment attack impact"""
        start_time = time.time()
        query = dns.message.make_query("fragment-monitor.example.com", "A")

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

    def _update_fragment_monitoring_phase(
        self,
        phase,
        current_time,
        attack_detected_time,
        response_time,
        status,
        thread_name,
    ):
        """Update monitoring phase based on fragment attack indicators"""
        # Detect fragment attack based on response time degradation
        if (phase == "baseline" and 
            (response_time > 200 or "FAILED" in status or "timeout" in status.lower())):
            
            if attack_detected_time is None:
                attack_detected_time = current_time
                phase = "during_attack"
                logging.warning(f"[{thread_name}] 🚨 UDP FRAGMENT DoS ATTACK DETECTED!")
        
        elif (phase == "during_attack" and 
              attack_detected_time and 
              (current_time - attack_detected_time) > (self.attack_duration + 10)):
            phase = "post_attack"
            logging.info(f"[{thread_name}] Post-fragment-attack recovery monitoring")

        return phase, attack_detected_time

    def _store_fragment_metric_data(self, phase, current_time, response_time, status):
        """Store fragment-specific metric data"""
        metric_data = {
            "timestamp": current_time,
            "phase": phase,
            "response_time_ms": response_time,
            "status": status,
            "fragment_attack_indicator": response_time > 200 or "timeout" in status.lower()
        }

        self.metrics[phase].append(metric_data)

    def _check_fragment_dos_conditions(self, phase, thread_name):
        """Check for fragment-specific DoS conditions"""
        if len(self.metrics[phase]) < 3:
            return

        recent_metrics = self.metrics[phase][-3:]
        recent_times = [m["response_time_ms"] for m in recent_metrics]
        recent_failures = sum(1 for m in recent_metrics if "FAILED" in m["status"])
        recent_timeouts = sum(1 for m in recent_metrics if "timeout" in m["status"].lower())

        avg_recent = mean(recent_times)

        # Fragment-specific DoS indicators
        fragment_dos_conditions = (
            avg_recent > 300 or           # Higher threshold for fragment attacks
            recent_failures >= 2 or       # 2+ failures in last 3 queries
            recent_timeouts >= 1 or       # Any timeout indicates severe impact
            max(recent_times) > 1000      # Any response > 1 second
        )

        if fragment_dos_conditions and phase != "during_attack":
            logging.warning(
                f"[{thread_name}] 🚨 Fragment DoS conditions detected: "
                f"avg={avg_recent:.2f}ms, failures={recent_failures}/3, timeouts={recent_timeouts}/3"
            )

    def _analyze_baseline_performance(self):
        """Analyze baseline performance before fragment attack"""
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

    def _analyze_fragment_attack_impact(self):
        """Analyze UDP fragment attack impact"""
        if not self.metrics["during_attack"]:
            return {}

        attack_times = [m["response_time_ms"] for m in self.metrics["during_attack"]]
        attack_failures = sum(
            1 for m in self.metrics["during_attack"] if "FAILED" in m["status"]
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
            "timeout_rate_percent": round(
                (attack_timeouts / len(self.metrics["during_attack"])) * 100, 2
            ),
            "sample_count": len(self.metrics["during_attack"]),
        }

        # Calculate performance degradation from fragment attack
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
        """Analyze recovery after fragment attack"""
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
        """Analyze legitimate client impact during fragment attack"""
        if not self.metrics["client_requests"]:
            return {}

        successful_clients = [
            r for r in self.metrics["client_requests"] if r["status"] in ["SUCCESS", "SUCCESS_SLOW", "SUCCESS_VERY_SLOW"]
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
                (len(degraded_clients) / len(self.metrics["client_requests"])) * 100,
                2,
            ),
            "avg_response_time_ms": (
                round(mean([r["response_time_ms"] for r in successful_clients]), 2)
                if successful_clients
                else 0
            ),
        }

    def _analyze_fragment_dos_indicators(self):
        """Analyze fragment-specific DoS indicators"""
        dos_data = {
            "fragment_attack_detected": len(self.metrics["during_attack"]) > 0,
            "max_response_degradation": 0,
            "service_disruption_detected": False,
            "memory_pressure_indicators": False,
            "fragment_reassembly_impact": "UNKNOWN"
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
            dos_data["service_disruption_detected"] = degradation > 300  # 300% degradation threshold
            dos_data["memory_pressure_indicators"] = degradation > 500   # Severe degradation indicates memory pressure

        # Analyze fragment reassembly impact
        if "fragment_attack_stats" in self.metrics:
            stats = self.metrics["fragment_attack_stats"]
            fragments_generated = stats.get("estimated_fragments", 0)
            
            if fragments_generated > 10000:
                dos_data["fragment_reassembly_impact"] = "SEVERE"
            elif fragments_generated > 5000:
                dos_data["fragment_reassembly_impact"] = "HIGH"
            elif fragments_generated > 1000:
                dos_data["fragment_reassembly_impact"] = "MODERATE"
            else:
                dos_data["fragment_reassembly_impact"] = "LOW"

        return dos_data

    def _print_fragment_report_summary(self, report):
        """Print fragment attack specific report summary"""
        print("\n" + "=" * 90)
        print("🎯 UDP FRAGMENTED FLOOD ATTACK SIMULATION REPORT")
        print("=" * 90)
        print("📦 ATTACK METHOD: IP Fragmentation Flood")
        print("   - Large UDP packets fragmented at IP layer")
        print("   - Forces target to consume resources reassembling fragments")
        print("   - Out-of-order fragment delivery increases processing overhead")
        print("   - Memory exhaustion through fragment buffer overflow")

        if "fragment_attack_stats" in self.metrics:
            stats = self.metrics["fragment_attack_stats"]
            print("\n🔥 FRAGMENT ATTACK STATISTICS:")
            print(f"   Fragmented Packets Sent: {stats.get('packets_sent', 0)}")
            print(f"   Estimated Fragments Generated: {stats.get('estimated_fragments', 0)}")
            print(f"   Packet Size Range: {stats.get('min_packet_size', 0)}-{stats.get('max_packet_size', 0)} bytes")
            print(f"   Attack Duration: {stats.get('duration', 0):.2f} seconds")
            print(f"   Attack Threads: {stats.get('threads', 0)}")
            print(f"   Fragment Overhead: {stats.get('fragment_overhead_bytes', 0)} bytes")

        if report["baseline_performance"]:
            baseline = report["baseline_performance"]
            print("\n📊 BASELINE PERFORMANCE:")
            print(f"   Average Response Time: {baseline['avg_response_time_ms']}ms")
            print(f"   Max Response Time: {baseline['max_response_time_ms']}ms")
            print(f"   Failure Rate: {baseline['failure_rate_percent']}%")

        if report["fragment_attack_impact"]:
            impact = report["fragment_attack_impact"]
            print("\n🚨 FRAGMENT ATTACK IMPACT:")
            print(f"   Average Response Time: {impact['avg_response_time_ms']}ms")
            print(f"   Max Response Time: {impact['max_response_time_ms']}ms")
            print(f"   Failure Rate: {impact['failure_rate_percent']}%")
            print(f"   Timeout Rate: {impact['timeout_rate_percent']}%")
            if "performance_degradation_percent" in impact:
                print(f"   Performance Degradation: {impact['performance_degradation_percent']}%")

        if report["client_impact"]:
            client = report["client_impact"]
            print("\n👥 LEGITIMATE CLIENT IMPACT:")
            print(f"   Success Rate: {client['success_rate_percent']}%")
            print(f"   Service Degradation: {client['degradation_rate_percent']}%")
            print(f"   Failed Requests: {client['failed_requests']}")
            print(f"   Average Response Time: {client['avg_response_time_ms']}ms")

        print("\n🔍 FRAGMENT DoS DETECTION:")
        dos = report["fragment_dos_indicators"]
        print(f"   Fragment Attack Detected: {'✅ YES' if dos['fragment_attack_detected'] else '❌ NO'}")
        print(f"   Service Disruption: {'✅ YES' if dos['service_disruption_detected'] else '❌ NO'}")
        print(f"   Memory Pressure: {'✅ YES' if dos['memory_pressure_indicators'] else '❌ NO'}")
        print(f"   Max Degradation: {dos['max_response_degradation']}%")
        print(f"   Fragment Reassembly Impact: {dos['fragment_reassembly_impact']}")

        print("\n📁 Detailed logs saved in: logs/ directory")
        print("   - dns_server_fragment_attack.log: DNS server under attack")
        print("   - client_requests_during_fragment_attack.log: Client experience")
        print("   - udp_fragment_attack.log: Attack execution details")
        print("   - fragment_dos_monitoring.log: DoS impact measurements")
        print("=" * 90)

    def generate_comprehensive_report(self):
        """Generate comprehensive fragment attack simulation report"""
        logging.info("Generating comprehensive UDP fragment attack simulation report...")

        report = {
            "simulation_summary": {
                "timestamp": datetime.now().isoformat(),
                "attack_type": "udp-fragmented-flood",
                "server": f"{self.server_ip}:{self.server_port}",
                "total_duration": len(self.metrics["baseline"])
                + len(self.metrics["during_attack"])
                + len(self.metrics["post_attack"]),
                "fragment_attack_config": {
                    "min_packet_size": self.min_packet_size,
                    "max_packet_size": self.max_packet_size,
                    "attack_threads": self.attack_threads,
                    "attack_duration": self.attack_duration
                }
            },
            "baseline_performance": self._analyze_baseline_performance(),
            "fragment_attack_impact": self._analyze_fragment_attack_impact(),
            "recovery_analysis": self._analyze_recovery(),
            "client_impact": self._analyze_client_impact(),
            "fragment_dos_indicators": self._analyze_fragment_dos_indicators(),
        }

        # Save detailed report
        with open("logs/udp_fragment_simulation_report.json", "w") as f:
            json.dump(report, f, indent=2)

        # Print summary
        self._print_fragment_report_summary(report)

        return report

    def cleanup(self):
        """Clean up DNS server process and resources"""
        logging.info("Starting UDP fragment simulation cleanup...")

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

        logging.info("UDP fragment simulation cleanup completed")

    def run_simulation(self):
        """Run the complete 4-thread UDP fragment flood attack simulation"""
        print("🚀 Starting 4-Thread UDP Fragmented Flood Attack Simulation")
        print("=" * 90)
        print("Thread 1: DNS Server - Target of fragmentation attack")
        print("Thread 2: Normal Client - Experiences service degradation")
        print("Thread 3: UDP Fragment Attack - Sends fragmented packets")
        print("Thread 4: Fragment DoS Monitor - Measures attack impact")
        print("=" * 90)
        print("Attack Type: UDP Fragmented Flood")
        print(f"Attack Parameters: Duration={self.attack_duration}s, Threads={self.attack_threads}")
        print(f"Packet Size Range: {self.min_packet_size}-{self.max_packet_size} bytes")
        print(f"Target Server: {self.server_ip}:{self.server_port}")
        print("=" * 90)

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
                    target=self.udp_fragment_attack_thread,
                    name="Thread-3-UDP-Fragment-Attack",
                ),
                threading.Thread(
                    target=self.fragment_dos_monitor_thread, name="Thread-4-Fragment-DoS-Monitor"
                ),
            ]

            # Start all threads with staggered timing
            for thread in threads:
                thread.start()
                logging.info(f"Started {thread.name}")
                time.sleep(1)  # Stagger thread starts

            logging.info("All threads started successfully - UDP fragment simulation running")

            # Wait for attack thread to complete (determines simulation end)
            threads[2].join()  # Wait for UDP fragment attack thread
            logging.info("UDP fragment attack thread completed")

            # Allow time for post-attack monitoring and recovery assessment
            time.sleep(10)

            # Signal stop and wait for other threads
            self.stop_event.set()

            for i, thread in enumerate(threads):
                if i != 2:  # Skip attack thread (already completed)
                    thread.join(timeout=10)
                    if thread.is_alive():
                        logging.warning(f"{thread.name} did not stop gracefully")

            # Generate comprehensive fragment attack report
            self.generate_comprehensive_report()

        except KeyboardInterrupt:
            logging.warning("UDP fragment simulation interrupted by user")
            self.stop_event.set()

        except Exception as e:
            logging.error(f"UDP fragment simulation failed: {e}")
            self.stop_event.set()

        finally:
            self.cleanup()


def main():
    parser = argparse.ArgumentParser(
        description="UDP Fragmented Flood Attack Simulation against DNS Server",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
UDP Fragmented Flood Attack Simulation

This simulation demonstrates the impact of UDP fragmentation attacks on DNS servers.
Large UDP packets are fragmented at the IP layer, forcing the target to consume
significant resources for fragment reassembly, potentially leading to memory
exhaustion and service degradation.

Attack Mechanism:
  1. Generate large UDP packets (larger than MTU)
  2. IP layer automatically fragments packets
  3. Send fragments out of order to maximize processing overhead
  4. Force target to allocate memory for fragment reassembly
  5. Overwhelm fragment reassembly buffers and timeouts

Examples:
  sudo python udp_fragment_attack_simulation.py --duration 30 --threads 10 --min-size 2000 --max-size 6000
  sudo python udp_fragment_attack_simulation.py --target-ip 192.168.1.100 --target-port 53 --max-size 8000
        """,
    )

    parser.add_argument(
        "--duration",
        "-d",
        type=int,
        default=30,
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
        "--min-size",
        type=int,
        default=1500,
        help="Minimum packet size in bytes (default: 1500)",
    )

    parser.add_argument(
        "--max-size",
        type=int,
        default=8000,
        help="Maximum packet size in bytes (default: 8000)",
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

    if args.min_size < 1000 or args.min_size > 65000:
        print("Error: Minimum packet size must be between 1000 and 65000 bytes")
        sys.exit(1)

    if args.max_size < args.min_size or args.max_size > 65000:
        print("Error: Maximum packet size must be >= minimum size and <= 65000 bytes")
        sys.exit(1)

    # Set logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    print("🎯 UDP Fragmented Flood Attack Simulation")
    print(f"Target: {args.target_ip}:{args.target_port}")
    print(f"Duration: {args.duration} seconds")
    print(f"Threads: {args.threads}")
    print(f"Packet Size Range: {args.min_size}-{args.max_size} bytes")
    print(f"Verbose Logging: {args.verbose}")
    print()

    # Confirm before starting
    try:
        confirm = input("Start the UDP fragment attack simulation? (yes/no): ").lower().strip()
        if confirm != "yes":
            print("UDP fragment attack simulation cancelled.")
            sys.exit(0)
    except KeyboardInterrupt:
        print("\nUDP fragment attack simulation cancelled.")
        sys.exit(0)

    simulation = UDPFragmentFloodSimulation(
        attack_duration=args.duration,
        attack_threads=args.threads,
        server_port=args.target_port,
        server_ip=args.target_ip,
        min_packet_size=args.min_size,
        max_packet_size=args.max_size,
    )

    # Handle Ctrl+C gracefully
    def signal_handler(sig, frame):
        logging.info("Received interrupt signal")
        simulation.stop_event.set()
        simulation.cleanup()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    # Run the UDP fragment attack simulation
    simulation.run_simulation()


if __name__ == "__main__":
    main()