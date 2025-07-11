#!/usr/bin/env python3
"""
DNS Gateway and Load Balancer
Extends the DNS server with proxy and load balancing capabilities
"""

import socket
import threading
import time
import logging
import dns.message
import dns.query
import dns.exception
from typing import List, Tuple, Dict, Optional
from concurrent.futures import ThreadPoolExecutor
import random

from .rate_limiter import RateLimiter
from .acl import ACL
from .metrics import MetricsCollector
from .tsig import TSIGAuthenticator


class DNSGateway:
    """
    DNS Gateway that provides load balancing and proxy functionality
    Routes queries to multiple backend DNS servers with health checking
    """
    
    def __init__(self, 
                 listen_address: str = "127.0.0.1",
                 listen_port: int = 53,
                 backend_servers: List[Tuple[str, int]] = None,
                 rate_limit_threshold: int = 100,
                 rate_limit_window: int = 5,
                 rate_limit_ban_duration: int = 300,
                 acl_rules: Dict = None,
                 health_check_interval: int = 30,
                 max_workers: int = 10,
                 tsig_key_name: str = None,
                 tsig_key_secret: str = None,
                 require_tsig: bool = False):
        """
        Initialize DNS Gateway
        
        Args:
            listen_address: Address to bind gateway
            listen_port: Port to bind gateway
            backend_servers: List of (host, port) backend DNS servers
            rate_limit_threshold: Max queries per IP in time window
            rate_limit_window: Time window for rate limiting (seconds)
            rate_limit_ban_duration: Ban duration for rate limited IPs (seconds)
            acl_rules: Access control rules
            health_check_interval: Health check frequency (seconds)
            max_workers: Maximum worker threads
            tsig_key_name: TSIG key name for backend authentication
            tsig_key_secret: TSIG key secret (base64) for backend authentication
            require_tsig: Whether to require TSIG authentication from clients
        """
        self.listen_address = listen_address
        self.listen_port = listen_port
        self.backend_servers = backend_servers or []
        self.healthy_servers = list(self.backend_servers)  # Track healthy servers
        self.current_server_index = 0
        self.health_check_interval = health_check_interval
        
        # TSIG configuration
        self.tsig_authenticator = None
        self.require_tsig = require_tsig
        if tsig_key_name and tsig_key_secret:
            self.tsig_authenticator = TSIGAuthenticator(tsig_key_name, tsig_key_secret)
            logging.info("TSIG authentication configured with key: %s", tsig_key_name)
        elif require_tsig:
            logging.warning("TSIG required but no key provided - gateway may fail to authenticate with backends")
        
        # Initialize security and monitoring components
        self.rate_limiter = RateLimiter(
            threshold=rate_limit_threshold,
            time_window=rate_limit_window,
            ban_duration=rate_limit_ban_duration
        )
        self.acl = ACL(**(acl_rules or {}))
        self.metrics = MetricsCollector()
        
        # Threading and networking
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.server_lock = threading.Lock()
        self.running = False
        
        # Statistics
        self.stats = {
            "total_queries": 0,
            "forwarded_queries": 0,
            "blocked_queries": 0,
            "backend_errors": 0,
            "health_checks": 0
        }
        
        logging.info("DNS Gateway initialized: listening on %s:%d", 
                    listen_address, listen_port)
        logging.info("Backend servers: %s", self.backend_servers)
    
    def add_backend_server(self, host: str, port: int) -> bool:
        """
        Add a backend DNS server to the pool
        
        Args:
            host: Server hostname/IP
            port: Server port
            
        Returns:
            True if server was added successfully
        """
        server = (host, port)
        with self.server_lock:
            if server not in self.backend_servers:
                self.backend_servers.append(server)
                self.healthy_servers.append(server)
                logging.info("Added backend server: %s:%d", host, port)
                return True
            logging.warning("Backend server %s:%d already exists", host, port)
            return False
    
    def remove_backend_server(self, host: str, port: int) -> bool:
        """
        Remove a backend DNS server from the pool
        
        Args:
            host: Server hostname/IP
            port: Server port
            
        Returns:
            True if server was removed successfully
        """
        server = (host, port)
        with self.server_lock:
            removed = False
            if server in self.backend_servers:
                self.backend_servers.remove(server)
                removed = True
            if server in self.healthy_servers:
                self.healthy_servers.remove(server)
                removed = True
            
            if removed:
                # Reset index if needed
                if self.current_server_index >= len(self.healthy_servers):
                    self.current_server_index = 0
                logging.info("Removed backend server: %s:%d", host, port)
                return True
            
            logging.warning("Backend server %s:%d not found", host, port)
            return False
    
    def get_next_server(self) -> Optional[Tuple[str, int]]:
        """
        Get next healthy server using round-robin load balancing
        
        Returns:
            Tuple of (host, port) for next server, or None if no healthy servers
        """
        with self.server_lock:
            if not self.healthy_servers:
                logging.error("No healthy backend servers available")
                return None
            
            # Round-robin selection
            server = self.healthy_servers[self.current_server_index]
            self.current_server_index = (self.current_server_index + 1) % len(self.healthy_servers)
            
            return server
    
    def get_random_server(self) -> Optional[Tuple[str, int]]:
        """
        Get a random healthy server (alternative to round-robin)
        
        Returns:
            Tuple of (host, port) for random server, or None if no healthy servers
        """
        with self.server_lock:
            if not self.healthy_servers:
                return None
            return random.choice(self.healthy_servers)
    
    def check_server_health(self, host: str, port: int) -> bool:
        """
        Check if a backend server is healthy by sending a simple query
        
        Args:
            host: Server hostname/IP
            port: Server port
            
        Returns:
            True if server responds to health check
        """
        try:
            # Create a simple query for health check
            query = dns.message.make_query('health.check.', 'A')
            
            # Sign the query if TSIG is configured
            if self.tsig_authenticator:
                query = self.tsig_authenticator.sign_request(query)
            
            # Try to query the server with a short timeout
            response = dns.query.udp(query, host, port=port, timeout=3)
            
            # Server is healthy if it responds (even with NXDOMAIN)
            return response is not None
            
        except Exception as e:
            logging.debug("Health check failed for %s:%d - %s", host, port, e)
            return False
    
    def health_check_worker(self):
        """
        Background worker that periodically checks backend server health
        """
        while self.running:
            try:
                time.sleep(self.health_check_interval)
                if not self.running:
                    break
                
                self.stats["health_checks"] += 1
                logging.debug("Performing health checks on %d backend servers", 
                            len(self.backend_servers))
                
                with self.server_lock:
                    healthy_servers = []
                    
                    for host, port in self.backend_servers:
                        if self.check_server_health(host, port):
                            healthy_servers.append((host, port))
                        else:
                            logging.warning("Backend server %s:%d failed health check", 
                                          host, port)
                    
                    # Update healthy servers list
                    old_count = len(self.healthy_servers)
                    self.healthy_servers = healthy_servers
                    new_count = len(self.healthy_servers)
                    
                    # Reset index if needed
                    if self.current_server_index >= new_count:
                        self.current_server_index = 0
                    
                    if old_count != new_count:
                        logging.info("Health check complete: %d/%d servers healthy", 
                                   new_count, len(self.backend_servers))
                
            except Exception as e:
                logging.error("Error in health check worker: %s", e)
    
    def forward_query(self, query_msg: dns.message.Message, 
                     client_addr: Tuple[str, int]) -> Optional[dns.message.Message]:
        """
        Forward a DNS query to a backend server
        
        Args:
            query_msg: DNS query message
            client_addr: Client address tuple
            
        Returns:
            DNS response message or None if forwarding failed
        """
        server = self.get_next_server()
        if not server:
            logging.error("No healthy backend servers to forward query")
            self.stats["backend_errors"] += 1
            return None
        
        host, port = server
        client_ip = client_addr[0]
        
        try:
            logging.debug("Forwarding query from %s to backend %s:%d", 
                         client_ip, host, port)
            
            # Create a new query message (copy) to avoid modifying original
            forward_query = dns.message.make_query(
                query_msg.question[0].name,
                query_msg.question[0].rdtype,
                query_msg.question[0].rdclass
            )
            forward_query.id = query_msg.id
            forward_query.flags = query_msg.flags
            
            # Sign the forwarded query if TSIG is configured
            if self.tsig_authenticator:
                forward_query = self.tsig_authenticator.sign_request(forward_query)
                logging.debug("Signed forwarded query with TSIG for backend %s:%d", host, port)
            
            # Forward query to backend server
            response = dns.query.udp(forward_query, host, port=port, timeout=10)
            self.stats["forwarded_queries"] += 1
            
            logging.debug("Received response from backend %s:%d for client %s", 
                         host, port, client_ip)
            
            return response
            
        except dns.exception.Timeout:
            logging.warning("Timeout forwarding query to backend %s:%d", host, port)
            self.stats["backend_errors"] += 1
            
            # Try with a different server if available
            alternative_server = self.get_random_server()
            if alternative_server and alternative_server != server:
                try:
                    alt_host, alt_port = alternative_server
                    logging.info("Retrying with alternative backend %s:%d", 
                               alt_host, alt_port)
                    
                    # Create and sign query for alternative server
                    alt_query = dns.message.make_query(
                        query_msg.question[0].name,
                        query_msg.question[0].rdtype,
                        query_msg.question[0].rdclass
                    )
                    alt_query.id = query_msg.id
                    alt_query.flags = query_msg.flags
                    
                    if self.tsig_authenticator:
                        alt_query = self.tsig_authenticator.sign_request(alt_query)
                    
                    response = dns.query.udp(alt_query, alt_host, port=alt_port, timeout=5)
                    self.stats["forwarded_queries"] += 1
                    return response
                except Exception as e:
                    logging.error("Alternative backend also failed: %s", e)
            
            return None
            
        except Exception as e:
            logging.error("Error forwarding query to backend %s:%d: %s", host, port, e)
            self.stats["backend_errors"] += 1
            return None
    
    def handle_client_request(self, data: bytes, client_addr: Tuple[str, int], sock: socket.socket):
        """
        Handle incoming DNS request from client
        
        Args:
            data: Raw DNS query data
            client_addr: Client address tuple
            sock: UDP socket for sending response
        """
        client_ip = client_addr[0]
        self.stats["total_queries"] += 1
        self.metrics.inc_queries()
        
        try:
            # Step 1: Rate limiting check
            if not self.rate_limiter.is_allowed(client_ip):
                logging.warning("Rate limit exceeded for client %s", client_ip)
                self.stats["blocked_queries"] += 1
                self.metrics.inc_errors()
                
                # Send rate limit exceeded response
                try:
                    query_msg = dns.message.from_wire(data)
                    error_response = dns.message.make_response(query_msg)
                    error_response.set_rcode(dns.rcode.REFUSED)
                    sock.sendto(error_response.to_wire(), client_addr)
                except Exception:
                    pass  # Best effort
                return
            
            # Step 2: ACL check
            if not self.acl.check(client_ip):
                logging.warning("ACL denied request from %s", client_ip)
                self.stats["blocked_queries"] += 1
                self.metrics.inc_errors()
                
                # Send access denied response
                try:
                    query_msg = dns.message.from_wire(data)
                    error_response = dns.message.make_response(query_msg)
                    error_response.set_rcode(dns.rcode.REFUSED)
                    sock.sendto(error_response.to_wire(), client_addr)
                except Exception:
                    pass  # Best effort
                return
            
            # Step 3: Parse DNS query with TSIG support
            query_msg = None
            tsig_valid = True
            
            try:
                if self.tsig_authenticator:
                    # Try to parse with TSIG keyring
                    query_msg = dns.message.from_wire(data, keyring=self.tsig_authenticator.keyring)
                    logging.debug("Successfully parsed TSIG-signed query from %s", client_ip)
                else:
                    # Parse without TSIG
                    query_msg = dns.message.from_wire(data)
            except dns.tsig.BadSignature:
                logging.warning("Invalid TSIG signature from client %s", client_ip)
                tsig_valid = False
                # Try to parse without TSIG for error response
                try:
                    query_msg = dns.message.from_wire(data)
                except Exception:
                    return
            except Exception as e:
                logging.error("Failed to parse query from %s: %s", client_ip, e)
                return
            
            # If TSIG is required and validation failed, reject the query
            if self.require_tsig and not tsig_valid:
                logging.warning("TSIG required but validation failed for client %s", client_ip)
                self.stats["blocked_queries"] += 1
                self.metrics.inc_errors()
                
                error_response = dns.message.make_response(query_msg)
                error_response.set_rcode(dns.rcode.NOTAUTH)
                sock.sendto(error_response.to_wire(), client_addr)
                return
            
            # Log query details
            if query_msg.question:
                q = query_msg.question[0]
                qname = str(q.name)
                qtype = dns.rdatatype.to_text(q.rdtype)
                logging.info("Gateway query from %s: %s %s", client_ip, qname, qtype)
            
            # Step 4: Forward query to backend
            response = self.forward_query(query_msg, client_addr)
            
            # Step 5: Send response back to client
            if response:
                sock.sendto(response.to_wire(), client_addr)
                logging.debug("Sent response to client %s", client_ip)
            else:
                # Send server failure response
                error_response = dns.message.make_response(query_msg)
                error_response.set_rcode(dns.rcode.SERVFAIL)
                sock.sendto(error_response.to_wire(), client_addr)
                logging.warning("Sent SERVFAIL to client %s (backend unavailable)", client_ip)
            
        except Exception as e:
            logging.error("Error handling request from %s: %s", client_ip, e)
            self.metrics.inc_errors()
            
            # Send server error response
            try:
                query_msg = dns.message.from_wire(data)
                error_response = dns.message.make_response(query_msg)
                error_response.set_rcode(dns.rcode.SERVFAIL)
                sock.sendto(error_response.to_wire(), client_addr)
            except Exception:
                pass  # Best effort
    
    def start(self):
        """
        Start the DNS Gateway server
        """
        if self.running:
            logging.warning("DNS Gateway is already running")
            return
        
        if not self.backend_servers:
            logging.error("No backend servers configured - cannot start gateway")
            return
        
        self.running = True
        
        # Create UDP socket
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((self.listen_address, self.listen_port))
            
            logging.info("DNS Gateway started on %s:%d", self.listen_address, self.listen_port)
            
            # Start health check worker
            self.executor.submit(self.health_check_worker)
            
            # Main server loop
            while self.running:
                try:
                    data, client_addr = self.socket.recvfrom(4096)
                    
                    # Handle request in thread pool
                    self.executor.submit(self.handle_client_request, data, client_addr, self.socket)
                    
                except socket.error as e:
                    if self.running:  # Only log if we're supposed to be running
                        logging.error("Socket error in gateway: %s", e)
                except Exception as e:
                    logging.error("Unexpected error in gateway main loop: %s", e)
            
        except Exception as e:
            logging.error("Failed to start DNS Gateway: %s", e)
        finally:
            self.stop()
    
    def stop(self):
        """
        Stop the DNS Gateway server
        """
        if not self.running:
            return
        
        logging.info("Stopping DNS Gateway...")
        self.running = False
        
        try:
            if hasattr(self, 'socket'):
                self.socket.close()
        except Exception:
            pass
        
        # Shutdown thread pool
        self.executor.shutdown(wait=True)
        
        logging.info("DNS Gateway stopped")
    
    def get_statistics(self) -> Dict:
        """
        Get gateway statistics
        
        Returns:
            Dictionary with current statistics
        """
        rate_limiter_stats = self.rate_limiter.get_stats()
        
        return {
            "gateway": {
                "total_queries": self.stats["total_queries"],
                "forwarded_queries": self.stats["forwarded_queries"],
                "blocked_queries": self.stats["blocked_queries"],
                "backend_errors": self.stats["backend_errors"],
                "health_checks": self.stats["health_checks"],
                "listen_address": f"{self.listen_address}:{self.listen_port}"
            },
            "backend_servers": {
                "total": len(self.backend_servers),
                "healthy": len(self.healthy_servers),
                "servers": self.backend_servers,
                "healthy_servers": self.healthy_servers
            },
            "rate_limiter": rate_limiter_stats,
            "acl": {
                "rules_count": len(self.acl.allowed_ips) + len(self.acl.blocked_ips)
            }
        }
    
    def reset_statistics(self):
        """
        Reset gateway statistics
        """
        self.stats = {
            "total_queries": 0,
            "forwarded_queries": 0,
            "blocked_queries": 0,
            "backend_errors": 0,
            "health_checks": 0
        }
        self.rate_limiter.reset_history()
        logging.info("Gateway statistics reset")


if __name__ == "__main__":
    # Example usage
    import argparse
    
    parser = argparse.ArgumentParser(description="DNS Gateway with Load Balancing")
    parser.add_argument("--listen-address", default="127.0.0.1", 
                       help="Gateway listen address")
    parser.add_argument("--listen-port", type=int, default=5353, 
                       help="Gateway listen port")
    parser.add_argument("--backend-servers", nargs="+", 
                       default=["127.0.0.1:5354", "127.0.0.1:7354"], 
                       help="Backend DNS servers (host:port)")
    parser.add_argument("--rate-limit-threshold", type=int, default=100,
                       help="Rate limit threshold (queries per window)")
    parser.add_argument("--rate-limit-window", type=int, default=5,
                       help="Rate limit time window (seconds)")
    parser.add_argument("--rate-limit-ban", type=int, default=300,
                       help="Rate limit ban duration (seconds)")
    parser.add_argument("--health-check-interval", type=int, default=30,
                       help="Health check interval (seconds)")
    parser.add_argument("--tsig-key-name", type=str,
                       help="TSIG key name for backend authentication")
    parser.add_argument("--tsig-key-secret", type=str,
                       help="TSIG key secret (base64) for backend authentication")
    parser.add_argument("--require-tsig", action="store_true",
                       help="Require TSIG authentication from clients")
    parser.add_argument("--tsig-key-file", type=str,
                       help="Path to TSIG key file (alternative to --tsig-key-name/secret)")
    
    args = parser.parse_args()
    
    # Parse backend servers
    backend_servers = []
    for server in args.backend_servers:
        if ':' in server:
            host, port = server.split(':')
            backend_servers.append((host, int(port)))
        else:
            backend_servers.append((server, 53))
    
    # Handle TSIG key configuration
    tsig_key_name = args.tsig_key_name
    tsig_key_secret = args.tsig_key_secret
    
    # If key file is provided, read from file
    if args.tsig_key_file:
        try:
            with open(args.tsig_key_file, 'r') as f:
                lines = f.readlines()
                for line in lines:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        parts = line.split()
                        if len(parts) >= 3:
                            tsig_key_name = parts[0]
                            tsig_key_secret = parts[2]
                            break
            if tsig_key_name and tsig_key_secret:
                logging.info("Loaded TSIG key from file: %s", args.tsig_key_file)
            else:
                logging.error("Failed to parse TSIG key from file: %s", args.tsig_key_file)
        except Exception as e:
            logging.error("Error reading TSIG key file %s: %s", args.tsig_key_file, e)
    
    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(message)s'
    )
    
    # Create and start gateway
    gateway = DNSGateway(
        listen_address=args.listen_address,
        listen_port=args.listen_port,
        backend_servers=backend_servers,
        rate_limit_threshold=args.rate_limit_threshold,
        rate_limit_window=args.rate_limit_window,
        rate_limit_ban_duration=args.rate_limit_ban,
        health_check_interval=args.health_check_interval,
        tsig_key_name=tsig_key_name,
        tsig_key_secret=tsig_key_secret,
        require_tsig=args.require_tsig
    )
    
    try:
        gateway.start()
    except KeyboardInterrupt:
        logging.info("Received interrupt signal")
    finally:
        gateway.stop()
