#!/usr/bin/env python3
"""
Rate Limiter and DOS Protection for DNS Server
Implements the security features from your DNS Gatekeeper
"""

import time
import threading
import logging
from typing import Dict, Tuple
from collections import defaultdict, deque

class RateLimiter:
    """
    High-performance rate limiting and DOS protection
    Optimized for high-volume scenarios
    """
    
    def __init__(self, threshold: int = 100, time_window: int = 5, ban_duration: int = 300, 
                 cleanup_interval: int = 60):
        """
        Initialize rate limiter
        
        Args:
            threshold: Maximum queries allowed in time window
            time_window: Time window in seconds for rate limiting
            ban_duration: Duration to block IPs in seconds
            cleanup_interval: How often to clean up old data (seconds)
        """
        self.threshold = threshold
        self.time_window = time_window
        self.ban_duration = ban_duration
        self.cleanup_interval = cleanup_interval
        
        # More efficient tracking using sliding window with timestamps
        self.request_timestamps: Dict[str, deque] = defaultdict(deque)
        self.blocked_ips: Dict[str, float] = {}  # {ip: unblock_time}
        
        # Thread lock for thread safety
        self.lock = threading.RLock()  # Use RLock for potential recursive calls
        
        # Statistics
        self.stats = {
            'total_requests': 0,
            'blocked_requests': 0,
            'rate_limited_ips': 0,
            'active_clients': 0
        }
        
        # Last cleanup time
        self.last_cleanup = time.time()
        
        logging.info("Rate limiter initialized: threshold=%d/%ds, ban=%ds, cleanup=%ds", 
                    threshold, time_window, ban_duration, cleanup_interval)
    
    def is_allowed(self, client_ip: str) -> bool:
        """
        Check if request from client IP should be allowed
        Optimized for high-volume processing
        
        Args:
            client_ip: Client IP address
            
        Returns:
            True if request should be allowed, False if blocked
        """
        if not client_ip:
            return True  # Allow if no IP provided
            
        current_time = time.time()
        
        with self.lock:
            self.stats['total_requests'] += 1
            
            # Periodic cleanup to prevent memory bloat
            if current_time - self.last_cleanup > self.cleanup_interval:
                self._cleanup_old_data(current_time)
                self.last_cleanup = current_time
            
            # Step 1: Check if IP is currently blocked (fast lookup)
            if client_ip in self.blocked_ips:
                if current_time < self.blocked_ips[client_ip]:
                    # Still blocked
                    self.stats['blocked_requests'] += 1
                    if self.stats['blocked_requests'] % 1000 == 0:  # Log every 1000th blocked request
                        logging.warning("Blocked request #%d from %s (banned until %s)", 
                                      self.stats['blocked_requests'], client_ip, 
                                      time.ctime(self.blocked_ips[client_ip]))
                    return False
                else:
                    # Unblock IP after ban duration
                    del self.blocked_ips[client_ip]
                    logging.info("Unblocked IP: %s", client_ip)
            
            # Step 2: Update request timestamps using sliding window
            timestamps = self.request_timestamps[client_ip]
            
            # Remove old timestamps outside the time window
            cutoff_time = current_time - self.time_window
            while timestamps and timestamps[0] < cutoff_time:
                timestamps.popleft()
            
            # Add current timestamp
            timestamps.append(current_time)
            
            # Check if IP exceeds rate limit
            if len(timestamps) > self.threshold:
                elapsed_time = current_time - timestamps[0]
                logging.warning("Rate limit exceeded for %s: %d requests in %.1fs (threshold: %d/%ds)", 
                              client_ip, len(timestamps), elapsed_time, 
                              self.threshold, self.time_window)
                
                # Ban the IP
                self.blocked_ips[client_ip] = current_time + self.ban_duration
                del self.request_timestamps[client_ip]  # Remove history for blocked IP
                self.stats['rate_limited_ips'] += 1
                self.stats['blocked_requests'] += 1
                
                logging.warning("Blocking %s for %d seconds due to excessive queries (total rate limited: %d)", 
                              client_ip, self.ban_duration, self.stats['rate_limited_ips'])
                return False
            
            return True
    
    def _cleanup_old_data(self, current_time: float):
        """
        Clean up old data to prevent memory bloat
        Called periodically during high-volume processing
        
        Args:
            current_time: Current timestamp
        """
        cleanup_start = time.time()
        
        # Clean up expired blocks
        expired_blocks = [ip for ip, unblock_time in self.blocked_ips.items() 
                        if current_time >= unblock_time]
        for ip in expired_blocks:
            del self.blocked_ips[ip]
        
        # Clean up old request timestamps
        cutoff_time = current_time - (self.time_window * 2)  # Keep extra buffer
        empty_ips = []
        
        for ip, timestamps in self.request_timestamps.items():
            # Remove old timestamps
            while timestamps and timestamps[0] < cutoff_time:
                timestamps.popleft()
            
            # Mark empty deques for removal
            if not timestamps:
                empty_ips.append(ip)
        
        # Remove empty deques
        for ip in empty_ips:
            del self.request_timestamps[ip]
        
        cleanup_time = time.time() - cleanup_start
        
        if expired_blocks or empty_ips:
            logging.debug("Cleanup completed in %.3fs: removed %d expired blocks, %d empty histories", 
                         cleanup_time, len(expired_blocks), len(empty_ips))
    
    def get_stats(self) -> Dict[str, any]:
        """
        Get current rate limiter statistics
        
        Returns:
            Dictionary with current stats
        """
        with self.lock:
            # Count active clients
            active_clients = len([ip for ip, timestamps in self.request_timestamps.items() 
                                if timestamps])
            
            # Update stats
            self.stats['active_clients'] = active_clients
            
            # Calculate efficiency metrics
            stats = self.stats.copy()
            stats.update({
                'blocked_ips_count': len(self.blocked_ips),
                'blocked_list': list(self.blocked_ips.keys())[:10],  # Limit to first 10
                'threshold': self.threshold,
                'time_window': self.time_window,
                'ban_duration': self.ban_duration,
                'memory_usage': {
                    'request_histories': len(self.request_timestamps),
                    'blocked_ips': len(self.blocked_ips),
                    'total_timestamps': sum(len(timestamps) for timestamps in self.request_timestamps.values())
                }
            })
            
            # Calculate blocking rate
            if stats['total_requests'] > 0:
                stats['blocking_rate'] = (stats['blocked_requests'] / stats['total_requests']) * 100
            else:
                stats['blocking_rate'] = 0.0
            
            return stats
    
    def reset_history(self):
        """
        Reset all request history (not blocked IPs)
        """
        with self.lock:
            self.request_timestamps.clear()
            self.stats['total_requests'] = 0
            self.stats['active_clients'] = 0
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
            self.request_timestamps.pop(client_ip, None)
            self.stats['rate_limited_ips'] += 1
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
