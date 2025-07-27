#!/usr/bin/env python3
"""
DNS Cookies Implementation (RFC 7873)
Provides defense against DNS amplification attacks and IP spoofing
"""

import time
import hmac
import hashlib
import secrets
import logging
import threading
from typing import Optional, Tuple, Dict
import struct
import ipaddress

class DNSCookieManager:
    """
    DNS Cookie manager implementing RFC 7873
    Provides lightweight authentication for DNS transactions
    """
    
    def __init__(self, secret_key: Optional[bytes] = None, 
                 secret_lifetime: int = 86400 * 30):  # 30 days default
        """
        Initialize DNS Cookie manager
        
        Args:
            secret_key: Server secret key (generates random if None)
            secret_lifetime: How long server secrets are valid (seconds)
        """
        self.secret_lifetime = secret_lifetime
        self.lock = threading.RLock()
        
        # Server secret management
        self.current_secret = secret_key or secrets.token_bytes(32)
        self.secret_created = time.time()
        self.old_secrets = []  # Keep old secrets for validation
        
        # Statistics
        self.stats = {
            'cookies_generated': 0,
            'cookies_validated': 0,
            'cookies_rejected': 0,
            'secret_rotations': 0
        }
        
        logging.info("DNS Cookie manager initialized with %d-day secret lifetime", 
                    secret_lifetime // 86400)
    
    def generate_client_cookie(self) -> bytes:
        """
        Generate a client cookie (64-bit random value)
        
        Returns:
            8-byte client cookie
        """
        return secrets.token_bytes(8)
    
    def generate_server_cookie(self, client_ip: str, client_cookie: bytes) -> bytes:
        """
        Generate server cookie using HMAC
        
        Args:
            client_ip: Client IP address
            client_cookie: Client's cookie value
            
        Returns:
            8-byte server cookie
        """
        with self.lock:
            self._rotate_secret_if_needed()
            
            # Create input for HMAC: client_ip + client_cookie + timestamp
            try:
                ip_bytes = ipaddress.ip_address(client_ip).packed
            except ValueError:
                # If IP parsing fails, use hash of IP string
                ip_bytes = hashlib.sha256(client_ip.encode()).digest()[:16]
            
            # Include current time (hour precision for cache efficiency)
            time_bytes = struct.pack('>I', int(time.time()) // 3600)
            
            input_data = ip_bytes + client_cookie + time_bytes
            
            # Generate HMAC using current secret
            hmac_obj = hmac.new(self.current_secret, input_data, hashlib.sha256)
            server_cookie = hmac_obj.digest()[:8]  # Take first 8 bytes
            
            self.stats['cookies_generated'] += 1
            return server_cookie
    
    def validate_server_cookie(self, client_ip: str, client_cookie: bytes, 
                             server_cookie: bytes, max_age: int = 3600) -> bool:
        """
        Validate a server cookie
        
        Args:
            client_ip: Client IP address
            client_cookie: Client's cookie value
            server_cookie: Server cookie to validate
            max_age: Maximum age of cookie in seconds
            
        Returns:
            True if cookie is valid
        """
        if len(server_cookie) != 8:
            self.stats['cookies_rejected'] += 1
            return False
        
        with self.lock:
            current_time = int(time.time()) // 3600
            
            # Try validating with current secret and recent time windows
            for time_offset in range(max_age // 3600 + 1):
                test_time = current_time - time_offset
                
                if self._validate_cookie_with_secret(client_ip, client_cookie, 
                                                   server_cookie, test_time, 
                                                   self.current_secret):
                    self.stats['cookies_validated'] += 1
                    return True
                
                # Also try with old secrets
                for old_secret, _ in self.old_secrets:
                    if self._validate_cookie_with_secret(client_ip, client_cookie,
                                                       server_cookie, test_time,
                                                       old_secret):
                        self.stats['cookies_validated'] += 1
                        return True
            
            self.stats['cookies_rejected'] += 1
            return False
    
    def _validate_cookie_with_secret(self, client_ip: str, client_cookie: bytes,
                                   server_cookie: bytes, time_hour: int, 
                                   secret: bytes) -> bool:
        """
        Validate cookie with specific secret and time
        
        Args:
            client_ip: Client IP
            client_cookie: Client cookie
            server_cookie: Server cookie to validate
            time_hour: Time in hours since epoch
            secret: Secret key to use
            
        Returns:
            True if valid
        """
        try:
            ip_bytes = ipaddress.ip_address(client_ip).packed
        except ValueError:
            ip_bytes = hashlib.sha256(client_ip.encode()).digest()[:16]
        
        time_bytes = struct.pack('>I', time_hour)
        input_data = ip_bytes + client_cookie + time_bytes
        
        expected_cookie = hmac.new(secret, input_data, hashlib.sha256).digest()[:8]
        
        # Constant-time comparison
        return hmac.compare_digest(server_cookie, expected_cookie)
    
    def _rotate_secret_if_needed(self):
        """
        Rotate server secret if it's too old
        """
        current_time = time.time()
        
        if current_time - self.secret_created > self.secret_lifetime:
            # Move current secret to old secrets
            self.old_secrets.append((self.current_secret, self.secret_created))
            
            # Generate new secret
            self.current_secret = secrets.token_bytes(32)
            self.secret_created = current_time
            self.stats['secret_rotations'] += 1
            
            # Clean up very old secrets (keep max 2 old secrets)
            if len(self.old_secrets) > 2:
                self.old_secrets = self.old_secrets[-2:]
            
            logging.info("Rotated DNS cookie server secret (rotation #%d)", 
                        self.stats['secret_rotations'])
    
    def get_stats(self) -> Dict:
        """
        Get cookie manager statistics
        
        Returns:
            Statistics dictionary
        """
        with self.lock:
            stats = self.stats.copy()
            stats.update({
                'secret_age_hours': (time.time() - self.secret_created) / 3600,
                'old_secrets_count': len(self.old_secrets),
                'validation_rate': (
                    self.stats['cookies_validated'] / 
                    max(1, self.stats['cookies_validated'] + self.stats['cookies_rejected'])
                ) * 100
            })
            return stats
    
    def force_secret_rotation(self):
        """
        Force immediate secret rotation (for testing)
        """
        with self.lock:
            self._rotate_secret_if_needed()
            # Force rotation by making current secret appear old
            self.secret_created = 0
            self._rotate_secret_if_needed()


def parse_cookie_option(opt_data: bytes) -> Tuple[Optional[bytes], Optional[bytes]]:
    """
    Parse DNS COOKIE option from EDNS(0) data
    
    Args:
        opt_data: Raw option data from EDNS(0)
        
    Returns:
        Tuple of (client_cookie, server_cookie) or (None, None) if invalid
    """
    if len(opt_data) < 8:
        return None, None
    
    client_cookie = opt_data[:8]
    server_cookie = opt_data[8:16] if len(opt_data) >= 16 else None
    
    return client_cookie, server_cookie


def create_cookie_option(client_cookie: bytes, server_cookie: Optional[bytes] = None) -> bytes:
    """
    Create DNS COOKIE option data for EDNS(0)
    
    Args:
        client_cookie: 8-byte client cookie
        server_cookie: Optional 8-byte server cookie
        
    Returns:
        Cookie option data
    """
    option_data = client_cookie
    if server_cookie:
        option_data += server_cookie
    return option_data