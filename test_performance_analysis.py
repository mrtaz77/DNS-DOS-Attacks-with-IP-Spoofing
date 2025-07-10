#!/usr/bin/env python3
"""
Enhanced Rate Limiting Test with Performance Analysis
Provides detailed metrics and tuning recommendations
"""

import time
import dns.message
import dns.query
import argparse
from concurrent.futures import ThreadPoolExecutor
import logging
from statistics import mean, median, stdev
import json

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

class DNSPerformanceTester:
    """Enhanced DNS performance and rate limiting tester"""
    
    def __init__(self, server_ip, server_port):
        self.server_ip = server_ip
        self.server_port = server_port
        self.response_times = []
        self.results = {
            "server": f"{server_ip}:{server_port}",
            "timestamp": time.time(),
            "tests": {}
        }
    
    def send_query_with_timing(self, query_name="www.example.com", query_type="A"):
        """Send DNS query and measure response time"""
        start_time = time.perf_counter()
        try:
            query = dns.message.make_query(query_name, query_type)
            response = dns.query.udp(query, self.server_ip, port=self.server_port, timeout=3)
            end_time = time.perf_counter()
            response_time = (end_time - start_time) * 1000  # Convert to milliseconds
            self.response_times.append(response_time)
            return True, response_time, f"Success: {response.rcode()}"
        except Exception as e:
            end_time = time.perf_counter()
            response_time = (end_time - start_time) * 1000
            return False, response_time, f"Failed: {e}"
    
    def test_baseline_performance(self, num_queries=100):
        """Test baseline performance without rate limiting pressure"""
        print(f"\n📊 Baseline Performance Test ({num_queries} queries)")
        
        response_times = []
        success_count = 0
        
        start_time = time.time()
        for i in range(num_queries):
            success, resp_time, _ = self.send_query_with_timing(f"baseline{i}.example.com")
            response_times.append(resp_time)
            if success:
                success_count += 1
            time.sleep(0.01)  # Small delay to avoid triggering rate limits
        
        end_time = time.time()
        duration = end_time - start_time
        
        # Calculate statistics
        avg_response = mean(response_times)
        median_response = median(response_times)
        min_response = min(response_times)
        max_response = max(response_times)
        std_response = stdev(response_times) if len(response_times) > 1 else 0
        
        results = {
            "total_queries": num_queries,
            "successful": success_count,
            "failed": num_queries - success_count,
            "duration": duration,
            "queries_per_second": num_queries / duration,
            "response_times": {
                "average_ms": round(avg_response, 2),
                "median_ms": round(median_response, 2),
                "min_ms": round(min_response, 2),
                "max_ms": round(max_response, 2),
                "std_dev_ms": round(std_response, 2)
            }
        }
        
        print(f"   Success Rate: {success_count}/{num_queries} ({success_count/num_queries*100:.1f}%)")
        print(f"   Average Response Time: {avg_response:.2f}ms")
        print(f"   Median Response Time: {median_response:.2f}ms")
        print(f"   95th Percentile: {sorted(response_times)[int(len(response_times)*0.95)]:.2f}ms")
        print(f"   Queries per Second: {num_queries/duration:.1f}")
        
        self.results["tests"]["baseline"] = results
        return results
    
    def test_rate_limit_thresholds(self):
        """Test different rate limit scenarios"""
        print(f"\n🎯 Rate Limit Threshold Testing")
        
        scenarios = [
            {"name": "Light Load", "qps": 10, "duration": 10},
            {"name": "Moderate Load", "qps": 25, "duration": 10},
            {"name": "Heavy Load", "qps": 50, "duration": 5},
            {"name": "Burst Attack", "qps": 100, "duration": 3}
        ]
        
        threshold_results = {}
        
        for scenario in scenarios:
            print(f"\n   Testing {scenario['name']}: {scenario['qps']} qps for {scenario['duration']}s")
            
            success_count = 0
            failure_count = 0
            response_times = []
            
            start_time = time.time()
            end_time = start_time + scenario['duration']
            query_interval = 1.0 / scenario['qps']
            
            query_count = 0
            while time.time() < end_time:
                success, resp_time, _ = self.send_query_with_timing(f"{scenario['name']}{query_count}.example.com")
                response_times.append(resp_time)
                
                if success:
                    success_count += 1
                else:
                    failure_count += 1
                
                query_count += 1
                time.sleep(max(0, query_interval - resp_time/1000))  # Adjust for response time
            
            actual_duration = time.time() - start_time
            total_queries = success_count + failure_count
            actual_qps = total_queries / actual_duration
            block_rate = failure_count / total_queries * 100 if total_queries > 0 else 0
            
            result = {
                "target_qps": scenario['qps'],
                "actual_qps": round(actual_qps, 1),
                "total_queries": total_queries,
                "successful": success_count,
                "blocked": failure_count,
                "block_rate_percent": round(block_rate, 1),
                "avg_response_ms": round(mean(response_times), 2) if response_times else 0
            }
            
            threshold_results[scenario['name']] = result
            
            print(f"      Actual QPS: {actual_qps:.1f}")
            print(f"      Success: {success_count}, Blocked: {failure_count}")
            print(f"      Block Rate: {block_rate:.1f}%")
        
        self.results["tests"]["thresholds"] = threshold_results
        return threshold_results
    
    def test_concurrent_clients(self, num_clients=5, queries_per_client=20):
        """Test multiple concurrent clients"""
        print(f"\n👥 Concurrent Clients Test ({num_clients} clients, {queries_per_client} queries each)")
        
        client_results = []
        
        def client_worker(client_id):
            success_count = 0
            response_times = []
            
            for i in range(queries_per_client):
                success, resp_time, _ = self.send_query_with_timing(f"client{client_id}-query{i}.example.com")
                response_times.append(resp_time)
                if success:
                    success_count += 1
                time.sleep(0.1)  # Small delay between queries
            
            return {
                "client_id": client_id,
                "successful": success_count,
                "failed": queries_per_client - success_count,
                "avg_response_ms": round(mean(response_times), 2) if response_times else 0
            }
        
        start_time = time.time()
        with ThreadPoolExecutor(max_workers=num_clients) as executor:
            futures = [executor.submit(client_worker, i) for i in range(num_clients)]
            client_results = [future.result() for future in futures]
        
        end_time = time.time()
        
        total_success = sum(r["successful"] for r in client_results)
        total_queries = num_clients * queries_per_client
        total_failed = total_queries - total_success
        
        result = {
            "num_clients": num_clients,
            "queries_per_client": queries_per_client,
            "total_queries": total_queries,
            "total_successful": total_success,
            "total_failed": total_failed,
            "duration": round(end_time - start_time, 2),
            "client_results": client_results
        }
        
        print(f"   Total Success: {total_success}/{total_queries} ({total_success/total_queries*100:.1f}%)")
        print(f"   Total Duration: {end_time - start_time:.2f}s")
        print(f"   Per-client breakdown:")
        for r in client_results:
            print(f"      Client {r['client_id']}: {r['successful']}/{queries_per_client} success, {r['avg_response_ms']:.2f}ms avg")
        
        self.results["tests"]["concurrent"] = result
        return result
    
    def generate_report(self):
        """Generate comprehensive performance report"""
        print(f"\n📋 COMPREHENSIVE PERFORMANCE REPORT")
        print("=" * 80)
        
        # Server info
        print(f"Server: {self.results['server']}")
        print(f"Test Time: {time.ctime(self.results['timestamp'])}")
        
        # Baseline performance
        if "baseline" in self.results["tests"]:
            baseline = self.results["tests"]["baseline"]
            print(f"\n🏃 BASELINE PERFORMANCE:")
            print(f"   Queries per Second: {baseline['queries_per_second']:.1f}")
            print(f"   Average Response: {baseline['response_times']['average_ms']:.2f}ms")
            print(f"   Success Rate: {baseline['successful']/baseline['total_queries']*100:.1f}%")
        
        # Rate limiting effectiveness
        if "thresholds" in self.results["tests"]:
            print(f"\n🛡️  RATE LIMITING EFFECTIVENESS:")
            thresholds = self.results["tests"]["thresholds"]
            for name, data in thresholds.items():
                print(f"   {name}: {data['block_rate_percent']:.1f}% blocked at {data['actual_qps']} qps")
        
        # Concurrent performance
        if "concurrent" in self.results["tests"]:
            concurrent = self.results["tests"]["concurrent"]
            print(f"\n👥 CONCURRENT CLIENT PERFORMANCE:")
            print(f"   {concurrent['num_clients']} clients: {concurrent['total_successful']}/{concurrent['total_queries']} success")
            print(f"   Fair distribution: {concurrent['total_successful']/concurrent['num_clients']:.1f} avg per client")
        
        # Recommendations
        print(f"\n💡 TUNING RECOMMENDATIONS:")
        
        if "baseline" in self.results["tests"]:
            baseline_qps = self.results["tests"]["baseline"]["queries_per_second"]
            print(f"   1. Baseline capacity: {baseline_qps:.0f} qps")
            print(f"   2. Recommended rate limit threshold: {int(baseline_qps * 0.8)} queries/window")
            print(f"   3. Suggested time window: 5-10 seconds")
        
        if "thresholds" in self.results["tests"]:
            heavy_blocked = thresholds.get("Heavy Load", {}).get("block_rate_percent", 0)
            if heavy_blocked < 50:
                print(f"   4. Consider lowering rate limit threshold (heavy load only {heavy_blocked:.1f}% blocked)")
            elif heavy_blocked > 90:
                print(f"   4. Consider raising rate limit threshold (heavy load {heavy_blocked:.1f}% blocked)")
            else:
                print(f"   4. Rate limiting threshold is well-tuned ({heavy_blocked:.1f}% heavy load blocked)")
        
        return self.results
    
    def save_results(self, filename=None):
        """Save results to JSON file"""
        if filename is None:
            filename = f"dns_performance_report_{int(time.time())}.json"
        
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        print(f"\n📄 Results saved to: {filename}")
        return filename

def main():
    parser = argparse.ArgumentParser(description="Enhanced DNS Performance and Rate Limiting Test")
    parser.add_argument("--server", default="127.0.0.1", help="DNS server IP")
    parser.add_argument("--port", type=int, default=5353, help="DNS server port")
    parser.add_argument("--baseline-queries", type=int, default=100, help="Number of baseline queries")
    parser.add_argument("--concurrent-clients", type=int, default=5, help="Number of concurrent clients")
    parser.add_argument("--save-report", action="store_true", help="Save results to JSON file")
    args = parser.parse_args()
    
    print("🚀 Enhanced DNS Performance and Rate Limiting Test")
    print("=" * 80)
    print(f"Target: {args.server}:{args.port}")
    
    tester = DNSPerformanceTester(args.server, args.port)
    
    try:
        # Test basic connectivity
        print("\n🔌 Testing connectivity...")
        success, _, result = tester.send_query_with_timing()
        if not success:
            print(f"❌ Cannot connect: {result}")
            return
        print("✅ Connectivity OK")
        
        # Run comprehensive tests
        tester.test_baseline_performance(args.baseline_queries)
        tester.test_rate_limit_thresholds()
        tester.test_concurrent_clients(args.concurrent_clients)
        
        # Generate report
        results = tester.generate_report()
        
        # Save results if requested
        if args.save_report:
            tester.save_results()
        
    except KeyboardInterrupt:
        print("\n🛑 Test interrupted")
    except Exception as e:
        print(f"\n❌ Test failed: {e}")

if __name__ == "__main__":
    main()
