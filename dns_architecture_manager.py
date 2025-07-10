#!/usr/bin/env python3
"""
DNS Architecture Manager
Demonstrates the complete enhanced DNS architecture with gateway
"""

import argparse
import subprocess
import time
import signal
import sys
import os
from concurrent.futures import ThreadPoolExecutor
import json

class DNSArchitectureManager:
    """
    Manages the complete DNS architecture with gateway load balancing
    """
    
    def __init__(self):
        self.processes = {}
        self.base_dir = "/home/amim/4-1/CSE 406-Computer Security/Project/DNS-DOS-Attacks-with-IP-Spoofing"
        
        # Configuration
        self.config = {
            "primary": {
                "udp_port": 5353,
                "tcp_port": 5354,
                "zone_file": "dns_server/zones/primary.zone"
            },
            "secondary1": {
                "udp_port": 7353,
                "tcp_port": 7354,
                "zone_file": "dns_server/zones/secondary1.zone"
            },
            "secondary2": {
                "udp_port": 8353,
                "tcp_port": 8354,
                "zone_file": "dns_server/zones/secondary2.zone"
            },
            "gateway": {
                "port": 9353,
                "rate_limit": 100,
                "time_window": 5,
                "ban_duration": 300
            },
            "tsig": {
                "name": "tsig-key-1752130646",
                "secret": "2vgKc8+OH9UMBrRYTBYOmjffLaCFVtGQPgXjt6fw05k="
            }
        }
    
    def cleanup(self, signum=None, frame=None):
        """Clean up all running processes"""
        # Parameters needed for signal handler compatibility
        _ = signum, frame  # Acknowledge unused parameters
        print("\n🧹 Cleaning up DNS architecture...")
        
        for name, process in self.processes.items():
            if process and process.poll() is None:
                print(f"  Stopping {name}...")
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
        
        print("✅ Cleanup complete")
        sys.exit(0)
    
    def start_dns_server(self, server_type):
        """Start a DNS server instance"""
        config = self.config[server_type]
        
        cmd = [
            "python", "-m", "dns_server.main",
            "--zone", config["zone_file"],
            "--addr", "127.0.0.1",
            "--port-udp", str(config["udp_port"]),
            "--port-tcp", str(config["tcp_port"]),
            "--tsig-name", self.config["tsig"]["name"],
            "--tsig-secret", self.config["tsig"]["secret"]
        ]
        
        # Add secondary-specific options
        if server_type.startswith("secondary"):
            cmd.extend([
                "--secondary",
                "--primary-server", "127.0.0.1",
                "--primary-port", str(self.config["primary"]["tcp_port"]),
                "--refresh-interval", "30"
            ])
        
        # Start the process
        log_file = f"logs/{server_type}.log"
        os.makedirs("logs", exist_ok=True)
        
        with open(log_file, "w") as f:
            process = subprocess.Popen(cmd, stdout=f, stderr=subprocess.STDOUT, cwd=self.base_dir)
        
        self.processes[server_type] = process
        time.sleep(2)  # Give it time to start
        
        if process.poll() is None:
            print(f"✅ {server_type.upper()} DNS server started (PID: {process.pid})")
            return True
        else:
            print(f"❌ {server_type.upper()} DNS server failed to start")
            return False
    
    def start_gateway(self):
        """Start the DNS Gateway"""
        backend_servers = [
            f"127.0.0.1:{self.config['primary']['udp_port']}",
            f"127.0.0.1:{self.config['secondary1']['udp_port']}",
            f"127.0.0.1:{self.config['secondary2']['udp_port']}"
        ]
        
        cmd = [
            "python", "-m", "dns_server.utils.dns_gateway",
            "--listen-address", "127.0.0.1",
            "--listen-port", str(self.config["gateway"]["port"]),
            "--backend-servers"] + backend_servers + [
            "--rate-limit-threshold", str(self.config["gateway"]["rate_limit"]),
            "--rate-limit-window", str(self.config["gateway"]["time_window"]),
            "--rate-limit-ban", str(self.config["gateway"]["ban_duration"]),
            "--health-check-interval", "15",
            "--tsig-key-file", "dns_server/keys/tsig-key-1752130646.key"
        ]
        
        log_file = "logs/gateway.log"
        with open(log_file, "w") as f:
            process = subprocess.Popen(cmd, stdout=f, stderr=subprocess.STDOUT, cwd=self.base_dir)
        
        self.processes["gateway"] = process
        time.sleep(3)  # Give it time to start
        
        if process.poll() is None:
            print(f"✅ DNS Gateway started (PID: {process.pid})")
            return True
        else:
            print("❌ DNS Gateway failed to start")
            return False
    
    def prepare_zones(self):
        """Prepare zone files for testing"""
        print("📋 Preparing zone files...")
        
        zone_content = """$ORIGIN example.com.
$TTL 3600
example.com. 3600 IN SOA ns1.example.com. admin.example.com. 2024071025 3600 1800 604800 3600
example.com. 3600 IN NS ns1.example.com.
ns1.example.com. 3600 IN A 192.168.1.1
www.example.com. 3600 IN A 192.168.1.10
api.example.com. 3600 IN A 192.168.1.50
gateway.example.com. 3600 IN A 10.0.0.100
test1.example.com. 3600 IN A 10.1.0.1
test2.example.com. 3600 IN A 10.1.0.2
"""
        
        os.makedirs("dns_server/zones", exist_ok=True)
        
        # Write all zone files
        for server_type in ["primary", "secondary1", "secondary2"]:
            zone_file = self.config[server_type]["zone_file"]
            with open(os.path.join(self.base_dir, zone_file), "w") as f:
                f.write(zone_content)
        
        print("✅ Zone files prepared")
    
    def start_architecture(self):
        """Start the complete DNS architecture"""
        print("🚀 Starting DNS Architecture with Gateway Load Balancing")
        print("=" * 60)
        
        # Prepare zone files
        self.prepare_zones()
        
        # Start DNS servers
        print("\n📡 Starting DNS Servers...")
        for server_type in ["primary", "secondary1", "secondary2"]:
            if not self.start_dns_server(server_type):
                print(f"❌ Failed to start {server_type} server")
                return False
        
        # Wait for servers to stabilize
        print("\n⏳ Waiting for DNS servers to stabilize...")
        time.sleep(5)
        
        # Start gateway
        print("\n🌐 Starting DNS Gateway...")
        if not self.start_gateway():
            print("❌ Failed to start gateway")
            return False
        
        # Wait for gateway to initialize
        print("\n⏳ Waiting for gateway to initialize...")
        time.sleep(3)
        
        print("\n✅ DNS Architecture started successfully!")
        print(f"🌐 Gateway listening on: 127.0.0.1:{self.config['gateway']['port']}")
        print(f"🏛️  Primary DNS: 127.0.0.1:{self.config['primary']['udp_port']}")
        print(f"🔄 Secondary1 DNS: 127.0.0.1:{self.config['secondary1']['udp_port']}")
        print(f"🔄 Secondary2 DNS: 127.0.0.1:{self.config['secondary2']['udp_port']}")
        
        return True
    
    def test_queries(self):
        """Test queries through different endpoints"""
        print("\n🔍 Testing DNS Queries...")
        print("=" * 40)
        
        test_records = ["www.example.com", "api.example.com", "gateway.example.com"]
        
        for record in test_records:
            print(f"\n🔍 Testing {record}:")
            
            # Test gateway
            result = subprocess.run([
                "dig", "@127.0.0.1", "-p", str(self.config["gateway"]["port"]),
                record, "A", "+short"
            ], capture_output=True, text=True)
            
            if result.returncode == 0 and result.stdout.strip():
                print(f"  Gateway: ✅ {result.stdout.strip()}")
            else:
                print(f"  Gateway: ❌ No response")
            
            # Test direct primary
            result = subprocess.run([
                "dig", "@127.0.0.1", "-p", str(self.config["primary"]["udp_port"]),
                record, "A", "+short"
            ], capture_output=True, text=True)
            
            if result.returncode == 0 and result.stdout.strip():
                print(f"  Direct:  ✅ {result.stdout.strip()}")
            else:
                print(f"  Direct:  ❌ No response")
    
    def test_load_balancing(self):
        """Test load balancing functionality"""
        print("\n⚖️  Testing Load Balancing...")
        print("=" * 40)
        
        print("🔄 Sending 10 queries through gateway to observe load balancing...")
        
        for i in range(1, 11):
            result = subprocess.run([
                "dig", "@127.0.0.1", "-p", str(self.config["gateway"]["port"]),
                "www.example.com", "A", "+short"
            ], capture_output=True, text=True)
            
            if result.returncode == 0 and result.stdout.strip():
                print(f"  Query {i:2d}: ✅ {result.stdout.strip()}")
            else:
                print(f"  Query {i:2d}: ❌ Failed")
            
            time.sleep(0.5)
    
    def test_rate_limiting(self):
        """Test rate limiting functionality"""
        print("\n🛡️  Testing Rate Limiting...")
        print("=" * 40)
        
        print("🚀 Sending rapid queries to test rate limiting...")
        
        success_count = 0
        total_queries = 20
        
        for i in range(1, total_queries + 1):
            result = subprocess.run([
                "dig", "@127.0.0.1", "-p", str(self.config["gateway"]["port"]),
                "test1.example.com", "A", "+short"
            ], capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0 and result.stdout.strip():
                success_count += 1
                status = "✅"
            else:
                status = "❌"
            
            print(f"  Query {i:2d}: {status}")
            time.sleep(0.1)  # Rapid queries
        
        blocked_count = total_queries - success_count
        print(f"\n📊 Rate limiting results:")
        print(f"  Successful: {success_count}/{total_queries}")
        print(f"  Blocked:    {blocked_count}/{total_queries}")
        
        if blocked_count > 0:
            print("✅ Rate limiting is working!")
        else:
            print("⚠️  No queries were blocked (rate limit may be too high)")
    
    def show_status(self):
        """Show status of all components"""
        print("\n📊 Architecture Status...")
        print("=" * 40)
        
        for name, process in self.processes.items():
            if process and process.poll() is None:
                print(f"  {name.upper()}: ✅ Running (PID: {process.pid})")
            else:
                print(f"  {name.upper()}: ❌ Stopped")
    
    def show_logs(self, component="gateway", lines=10):
        """Show logs for a component"""
        log_file = f"logs/{component}.log"
        
        if os.path.exists(log_file):
            print(f"\n📋 {component.upper()} Logs (last {lines} lines):")
            print("=" * 50)
            
            result = subprocess.run(["tail", "-n", str(lines), log_file], 
                                  capture_output=True, text=True)
            if result.stdout:
                for line in result.stdout.strip().split('\n'):
                    print(f"  {line}")
            else:
                print("  No logs available")
        else:
            print(f"❌ Log file not found: {log_file}")
    
    def interactive_mode(self):
        """Run in interactive mode"""
        print("\n🎮 Interactive Mode")
        print("=" * 30)
        print("Commands:")
        print("  status   - Show component status")
        print("  test     - Run basic query tests")
        print("  balance  - Test load balancing")
        print("  ratelimit- Test rate limiting")
        print("  logs     - Show gateway logs")
        print("  logs <component> - Show specific component logs")
        print("  quit     - Exit")
        
        while True:
            try:
                cmd = input("\nDNS> ").strip().split()
                if not cmd:
                    continue
                
                if cmd[0] == "quit":
                    break
                elif cmd[0] == "status":
                    self.show_status()
                elif cmd[0] == "test":
                    self.test_queries()
                elif cmd[0] == "balance":
                    self.test_load_balancing()
                elif cmd[0] == "ratelimit":
                    self.test_rate_limiting()
                elif cmd[0] == "logs":
                    component = cmd[1] if len(cmd) > 1 else "gateway"
                    self.show_logs(component)
                else:
                    print("❌ Unknown command")
                    
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"❌ Error: {e}")
    
    def run_demo(self):
        """Run automated demo"""
        print("🎭 Running Automated Demo...")
        print("=" * 40)
        
        # Start architecture
        if not self.start_architecture():
            return False
        
        # Run tests
        self.test_queries()
        self.test_load_balancing()
        self.test_rate_limiting()
        self.show_status()
        self.show_logs()
        
        print("\n✅ Demo completed!")
        return True


def main():
    parser = argparse.ArgumentParser(description="DNS Architecture Manager")
    parser.add_argument("--mode", choices=["demo", "interactive", "start"], 
                       default="demo", help="Operation mode")
    parser.add_argument("--no-cleanup", action="store_true", 
                       help="Don't auto-cleanup on exit")
    
    args = parser.parse_args()
    
    manager = DNSArchitectureManager()
    
    # Setup signal handlers for cleanup
    if not args.no_cleanup:
        signal.signal(signal.SIGINT, manager.cleanup)
        signal.signal(signal.SIGTERM, manager.cleanup)
    
    try:
        if args.mode == "demo":
            manager.run_demo()
            input("\nPress Enter to exit...")
        elif args.mode == "start":
            if manager.start_architecture():
                print("\n🎯 Architecture started. Use Ctrl+C to stop.")
                while True:
                    time.sleep(1)
        elif args.mode == "interactive":
            if manager.start_architecture():
                manager.interactive_mode()
    
    except KeyboardInterrupt:
        pass
    finally:
        if not args.no_cleanup:
            manager.cleanup()


if __name__ == "__main__":
    main()
