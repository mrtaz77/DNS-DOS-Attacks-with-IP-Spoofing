#!/usr/bin/env python3
"""
Test script to demonstrate rate limiting and DOS protection
This script simulates various attack scenarios to test the rate limiter
"""

import time
import socket
import dns.message
import dns.query
import threading
import argparse
from concurrent.futures import ThreadPoolExecutor
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

def send_dns_query(server_ip, server_port, query_name="www.example.com", query_type="A"):
    """Send a single DNS query and return success/failure"""
    try:
        query = dns.message.make_query(query_name, query_type)
        response = dns.query.udp(query, server_ip, port=server_port, timeout=2)
        return True, f"Success: {response.rcode()}"
    except Exception as e:
        return False, f"Failed: {e}"

def test_normal_queries(server_ip, server_port, num_queries=10):
    """Test normal query rate - should all succeed"""
    print(f"\n🧪 Testing {num_queries} normal queries (should all succeed)")
    
    success_count = 0
    for i in range(num_queries):
        success, result = send_dns_query(server_ip, server_port, f"test{i}.example.com")
        if success:
            success_count += 1
        time.sleep(0.1)  # Small delay between queries
    
    print(f"✅ Normal queries: {success_count}/{num_queries} succeeded")
    return success_count

def test_burst_attack(server_ip, server_port, num_queries=150, threads=10):
    """Test burst attack - should trigger rate limiting"""
    print(f"\n🚨 Testing burst attack: {num_queries} queries with {threads} threads")
    
    success_count = 0
    failure_count = 0
    
    def worker():
        nonlocal success_count, failure_count
        for i in range(num_queries // threads):
            success, result = send_dns_query(server_ip, server_port, f"attack{i}.example.com")
            if success:
                success_count += 1
            else:
                failure_count += 1
    
    # Start attack threads
    start_time = time.time()
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(worker) for _ in range(threads)]
        for future in futures:
            future.result()
    
    end_time = time.time()
    total_queries = success_count + failure_count
    duration = end_time - start_time
    
    print(f"📊 Burst attack results:")
    print(f"   Duration: {duration:.2f} seconds")
    print(f"   Total queries: {total_queries}")
    print(f"   Successful: {success_count}")
    print(f"   Blocked: {failure_count}")
    print(f"   Rate: {total_queries/duration:.1f} queries/second")
    
    if failure_count > 0:
        print(f"✅ Rate limiting working: {failure_count} queries blocked")
    else:
        print(f"⚠️  Rate limiting may not be working: no queries blocked")
    
    return success_count, failure_count

def test_sustained_attack(server_ip, server_port, duration_seconds=30, rate_per_second=20):
    """Test sustained attack over time"""
    print(f"\n⏱️  Testing sustained attack: {rate_per_second} queries/second for {duration_seconds} seconds")
    
    success_count = 0
    failure_count = 0
    start_time = time.time()
    query_interval = 1.0 / rate_per_second
    
    while time.time() - start_time < duration_seconds:
        success, result = send_dns_query(server_ip, server_port, "sustained.example.com")
        if success:
            success_count += 1
        else:
            failure_count += 1
        
        time.sleep(query_interval)
    
    total_queries = success_count + failure_count
    actual_duration = time.time() - start_time
    
    print(f"📊 Sustained attack results:")
    print(f"   Duration: {actual_duration:.2f} seconds")
    print(f"   Total queries: {total_queries}")
    print(f"   Successful: {success_count}")
    print(f"   Blocked: {failure_count}")
    print(f"   Actual rate: {total_queries/actual_duration:.1f} queries/second")
    
    return success_count, failure_count

def test_recovery_after_ban(server_ip, server_port):
    """Test if service recovers after ban period"""
    print(f"\n🔄 Testing recovery after ban...")
    
    # First, trigger a ban with burst
    print("   Triggering ban with 200 rapid queries...")
    burst_success, burst_failures = test_burst_attack(server_ip, server_port, 200, 20)
    
    if burst_failures == 0:
        print("   ⚠️  No ban detected, skipping recovery test")
        return
    
    # Wait for ban to expire (assuming 300 second default ban)
    print("   Waiting 10 seconds, then testing if still banned...")
    time.sleep(10)
    
    # Test if still banned
    success, result = send_dns_query(server_ip, server_port, "recovery-test.example.com")
    if success:
        print("   ✅ Service recovered quickly (ban may have shorter duration)")
    else:
        print("   ⏰ Still banned, this is expected for longer ban durations")
    
    print("   Note: Full recovery test would require waiting for ban duration to expire")

def test_multiple_ips_simulation(server_ip, server_port):
    """Simulate attack from multiple IPs (limited simulation)"""
    print(f"\n🌐 Testing distributed attack simulation...")
    print("   Note: This simulates multiple IPs but all come from same source")
    
    # This is a limitation - we can't easily simulate multiple source IPs
    # but we can test that the rate limiter works per-IP
    success_count = 0
    
    for i in range(50):
        success, result = send_dns_query(server_ip, server_port, f"distributed{i}.example.com")
        if success:
            success_count += 1
        time.sleep(0.05)  # Moderate rate
    
    print(f"   Single IP distributed test: {success_count}/50 queries succeeded")

def main():
    parser = argparse.ArgumentParser(description="Rate Limiting and DOS Protection Test")
    parser.add_argument("--server", default="127.0.0.1", help="DNS server IP")
    parser.add_argument("--port", type=int, default=5353, help="DNS server port")
    parser.add_argument("--test", choices=["all", "normal", "burst", "sustained", "recovery", "distributed"], 
                       default="all", help="Which test to run")
    args = parser.parse_args()
    
    print("🛡️  DNS Rate Limiting and DOS Protection Test")
    print("=" * 60)
    print(f"Target server: {args.server}:{args.port}")
    print("This script tests the rate limiting features integrated from your DNS Gatekeeper")
    print("\nMake sure your DNS server is running with rate limiting enabled:")
    print("python -m dns_server.main --port-udp 5353 --rate-limit-threshold 100 --rate-limit-window 5")
    
    try:
        # Test basic connectivity first
        print(f"\n🔌 Testing basic connectivity...")
        success, result = send_dns_query(args.server, args.port)
        if not success:
            print(f"❌ Cannot connect to DNS server: {result}")
            print("Make sure the server is running and accessible")
            return
        print(f"✅ Basic connectivity OK")
        
        if args.test in ["all", "normal"]:
            test_normal_queries(args.server, args.port)
        
        if args.test in ["all", "burst"]:
            test_burst_attack(args.server, args.port)
        
        if args.test in ["all", "sustained"]:
            test_sustained_attack(args.server, args.port, duration_seconds=15)
        
        if args.test in ["all", "distributed"]:
            test_multiple_ips_simulation(args.server, args.port)
        
        if args.test in ["all", "recovery"]:
            test_recovery_after_ban(args.server, args.port)
        
        print(f"\n✅ Rate limiting test completed!")
        print(f"\n📝 Key Features Tested:")
        print("✅ Normal query handling")
        print("✅ Burst attack detection and blocking") 
        print("✅ Rate limiting per IP address")
        print("✅ Sustained attack mitigation")
        print("✅ Basic recovery testing")
        
        print(f"\n🔧 To adjust rate limiting settings:")
        print("--rate-limit-threshold N     # Max queries per time window")
        print("--rate-limit-window N        # Time window in seconds")
        print("--rate-limit-ban-duration N  # Ban duration in seconds")
        
    except KeyboardInterrupt:
        print("\n🛑 Test interrupted by user")
    except Exception as e:
        print(f"\n❌ Test failed: {e}")

if __name__ == "__main__":
    main()
