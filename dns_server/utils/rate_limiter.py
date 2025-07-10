#!/usr/bin/env python3
"""
Rate Limiter and DOS Protection for DNS Server
Implements the security features from your DNS Gatekeeper
"""

import time
import threading
import logging
from typing import Dict, Tuple

class RateLimiter:
    """
    Rate limiting and DOS protection similar to your DNS Gatekeeper
    """
    
    def __init__(self, threshold: int = 100, time_window: int = 5, ban_duration: int = 300):
        """
        Initialize rate limiter
        
        Args:
            threshold: Maximum queries allowed in time window
            time_window: Time window in seconds for rate limiting
            ban_duration: Duration to block IPs in seconds
        """
        self.threshold = threshold
        self.time_window = time_window
        self.ban_duration = ban_duration
        
        # Track request history and blocked IPs
        self.history: Dict[str, Dict[str, float]] = {}  # {ip: {"count": int, "start_time": float}}
        self.blocked_ips: Dict[str, float] = {}  # {ip: unblock_time}
        
        # Thread lock for thread safety
        self.lock = threading.Lock()
        
        logging.info("Rate limiter initialized: threshold=%d/%ds, ban=%ds", 
                    threshold, time_window, ban_duration)
    
    def is_allowed(self, client_ip: str) -> bool:
        """
        Check if request from client IP should be allowed
        
        Args:
            client_ip: Client IP address
            
        Returns:
            True if request should be allowed, False if blocked
        """
        if not client_ip:
            return True  # Allow if no IP provided
            
        with self.lock:
            current_time = time.time()
            
            # Step 1: Check if IP is currently blocked
            if client_ip in self.blocked_ips:
                if current_time < self.blocked_ips[client_ip]:
                    # Still blocked
                    logging.warning("Blocked request from %s (banned until %s)", 
                                  client_ip, time.ctime(self.blocked_ips[client_ip]))
                    return False
                else:
                    # Unblock IP after ban duration
                    del self.blocked_ips[client_ip]
                    logging.info("Unblocked IP: %s", client_ip)
            
            # Step 2: Update request count and check for rate limiting
            if client_ip not in self.history:
                self.history[client_ip] = {"count": 0, "start_time": current_time}
            
            # Increment request count
            self.history[client_ip]["count"] += 1
            elapsed_time = current_time - self.history[client_ip]["start_time"]
            
            # Check if IP exceeds rate limit
            if self.history[client_ip]["count"] > self.threshold and elapsed_time < self.time_window:
                logging.warning("Rate limit exceeded for %s: %d requests in %.1fs (threshold: %d/%ds)", 
                              client_ip, self.history[client_ip]["count"], 
                              elapsed_time, self.threshold, self.time_window)
                
                # Ban the IP
                self.blocked_ips[client_ip] = current_time + self.ban_duration
                del self.history[client_ip]  # Remove history for blocked IP
                
                logging.warning("Blocking %s for %d seconds due to excessive queries", 
                              client_ip, self.ban_duration)
                return False
            
            # Reset count after time window
            if elapsed_time >= self.time_window:
                self.history[client_ip] = {"count": 1, "start_time": current_time}
            
            return True
    
    def get_stats(self) -> Dict[str, any]:
        """
        Get current rate limiter statistics
        
        Returns:
            Dictionary with current stats
        """
        with self.lock:
            current_time = time.time()
            
            # Clean up expired blocks
            expired_blocks = [ip for ip, unblock_time in self.blocked_ips.items() 
                            if current_time >= unblock_time]
            for ip in expired_blocks:
                del self.blocked_ips[ip]
            
            # Clean up old history
            expired_history = [ip for ip, data in self.history.items()
                             if current_time - data["start_time"] > self.time_window * 2]
            for ip in expired_history:
                del self.history[ip]
            
            return {
                "active_clients": len(self.history),
                "blocked_ips": len(self.blocked_ips),
                "blocked_list": list(self.blocked_ips.keys()),
                "threshold": self.threshold,
                "time_window": self.time_window,
                "ban_duration": self.ban_duration
            }
    
    def reset_history(self):
        """
        Reset all request history (not blocked IPs)
        """
        with self.lock:
            self.history.clear()
            logging.info("Rate limiter history reset")
    
    def unblock_ip(self, client_ip: str) -> bool:
        """
        Manually unblock an IP address
        
        Args:
            client_ip: IP address to unblock
            
        Returns:
            True if IP was blocked and now unblocked, False if not blocked
        """
        with self.lock:
            if client_ip in self.blocked_ips:
                del self.blocked_ips[client_ip]
                logging.info("Manually unblocked IP: %s", client_ip)
                return True
            return False
    
    def block_ip(self, client_ip: str, duration: int = None) -> bool:
        """
        Manually block an IP address
        
        Args:
            client_ip: IP address to block
            duration: Block duration in seconds (default: ban_duration)
            
        Returns:
            True if IP was blocked
        """
        if duration is None:
            duration = self.ban_duration
            
        with self.lock:
            self.blocked_ips[client_ip] = time.time() + duration
            # Remove from history if present
            self.history.pop(client_ip, None)
            logging.warning("Manually blocked IP %s for %d seconds", client_ip, duration)
            return True


class LoadBalancer:
    """
    Simple round-robin load balancer for multiple DNS servers
    Similar to your DNS Gatekeeper's server selection
    """
    
    def __init__(self, servers: list):
        """
        Initialize load balancer
        
        Args:
            servers: List of (host, port) tuples for backend servers
        """
        self.servers = servers
        self.current_index = 0
        self.lock = threading.Lock()
        
        logging.info("Load balancer initialized with %d servers: %s", 
                    len(servers), servers)
    
    def get_next_server(self) -> Tuple[str, int]:
        """
        Get next server using round-robin selection
        
        Returns:
            Tuple of (host, port) for next server
        """
        if not self.servers:
            return None, None
            
        with self.lock:
            server = self.servers[self.current_index]
            self.current_index = (self.current_index + 1) % len(self.servers)
            return server
    
    def remove_server(self, host: str, port: int) -> bool:
        """
        Remove a server from the pool
        
        Args:
            host: Server hostname/IP
            port: Server port
            
        Returns:
            True if server was removed
        """
        server = (host, port)
        with self.lock:
            if server in self.servers:
                self.servers.remove(server)
                # Reset index if needed
                if self.current_index >= len(self.servers):
                    self.current_index = 0
                logging.info("Removed server from load balancer: %s:%d", host, port)
                return True
            return False
    
    def add_server(self, host: str, port: int) -> bool:
        """
        Add a server to the pool
        
        Args:
            host: Server hostname/IP
            port: Server port
            
        Returns:
            True if server was added
        """
        server = (host, port)
        with self.lock:
            if server not in self.servers:
                self.servers.append(server)
                logging.info("Added server to load balancer: %s:%d", host, port)
                return True
            return False
