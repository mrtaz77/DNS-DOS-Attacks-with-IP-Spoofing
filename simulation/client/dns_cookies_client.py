#!/usr/bin/env python3
"""
DNS Cookies Client Implementation (RFC 7873)
Client-side support for DNS cookies to prevent spoofing attacks
"""

import secrets
import struct
from typing import Optional, Tuple, Dict


class DNSCookieClient:
    """
    Client-side DNS Cookie manager
    Generates client cookies and stores server cookies
    """
    
    def __init__(self):
        """Initialize DNS Cookie client"""
        # Store server cookies by server IP
        self.server_cookies: Dict[str, bytes] = {}
        
    def generate_client_cookie(self) -> bytes:
        """
        Generate a new 8-byte client cookie
        
        Returns:
            8-byte random client cookie
        """
        return secrets.token_bytes(8)
    
    def store_server_cookie(self, server_ip: str, server_cookie: bytes):
        """
        Store server cookie for future requests
        
        Args:
            server_ip: DNS server IP address
            server_cookie: 8-byte server cookie received from server
        """
        if len(server_cookie) == 8:
            self.server_cookies[server_ip] = server_cookie
    
    def get_server_cookie(self, server_ip: str) -> Optional[bytes]:
        """
        Get stored server cookie for a server
        
        Args:
            server_ip: DNS server IP address
            
        Returns:
            8-byte server cookie or None if not stored
        """
        return self.server_cookies.get(server_ip)
    
    def create_cookie_option(self, client_cookie: bytes, 
                           server_cookie: Optional[bytes] = None) -> bytes:
        """
        Create EDNS(0) DNS Cookie option data
        
        Args:
            client_cookie: 8-byte client cookie
            server_cookie: Optional 8-byte server cookie
            
        Returns:
            Cookie option data for EDNS(0)
        """
        option_data = client_cookie
        if server_cookie:
            option_data += server_cookie
        return option_data
    
    def parse_cookie_option(self, opt_data: bytes) -> Tuple[Optional[bytes], Optional[bytes]]:
        """
        Parse DNS Cookie option from EDNS(0) response
        
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


def add_cookie_to_dns_query(query_packet: bytes, client_cookie: bytes, 
                          server_cookie: Optional[bytes] = None) -> bytes:
    """
    Add DNS Cookie option to an existing DNS query packet
    
    Args:
        query_packet: Original DNS query packet
        client_cookie: 8-byte client cookie
        server_cookie: Optional 8-byte server cookie
        
    Returns:
        Modified DNS query packet with EDNS(0) cookie option
    """
    if len(query_packet) < 12:
        return query_packet  # Invalid packet
    
    # Parse original header
    header = query_packet[:12]
    rest = query_packet[12:]
    
    # Unpack header to modify ARCOUNT
    txid, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", header)
    
    # Create cookie option data
    cookie_option = client_cookie
    if server_cookie:
        cookie_option += server_cookie
    
    # Create EDNS(0) OPT record with cookie option
    # OPT record format:
    # - NAME: . (root) = 0x00
    # - TYPE: OPT (41) = 0x0029
    # - CLASS: UDP payload size (usually 4096) = 0x1000
    # - TTL: Extended RCODE and flags (usually 0) = 0x00000000
    # - RDLENGTH: length of option data
    # - RDATA: option data
    
    opt_record = b'\x00'  # ROOT name (.)
    opt_record += struct.pack('!H', 41)  # TYPE = OPT
    opt_record += struct.pack('!H', 4096)  # CLASS = UDP payload size
    opt_record += struct.pack('!I', 0)  # TTL = extended flags
    
    # Option data: OPTION-CODE (10) + OPTION-LENGTH + OPTION-DATA
    option_data = struct.pack('!HH', 10, len(cookie_option)) + cookie_option
    opt_record += struct.pack('!H', len(option_data)) + option_data
    
    # Update ARCOUNT
    arcount += 1
    new_header = struct.pack("!HHHHHH", txid, flags, qdcount, ancount, nscount, arcount)
    
    return new_header + rest + opt_record


def extract_cookie_from_response(response_packet: bytes) -> Tuple[Optional[bytes], Optional[bytes]]:
    """
    Extract DNS Cookie from response packet
    
    Args:
        response_packet: DNS response packet
        
    Returns:
        Tuple of (client_cookie, server_cookie) or (None, None) if not found
    """
    if len(response_packet) < 12:
        return None, None
    
    # Parse header
    header = response_packet[:12]
    txid, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", header)
    
    if arcount == 0:
        return None, None  # No additional records
    
    # Skip question section
    offset = 12
    for _ in range(qdcount):
        # Skip QNAME
        while offset < len(response_packet) and response_packet[offset] != 0:
            label_len = response_packet[offset]
            if label_len & 0xC0:  # Compression
                offset += 2
                break
            else:
                offset += 1 + label_len
        else:
            if offset < len(response_packet):
                offset += 1  # Skip final 0
        
        # Skip QTYPE and QCLASS
        offset += 4
    
    # Skip answer and authority sections
    for _ in range(ancount + nscount):
        # Skip NAME (with compression support)
        if offset >= len(response_packet):
            return None, None
        
        if response_packet[offset] & 0xC0:  # Compression
            offset += 2
        else:
            # Skip labels
            while offset < len(response_packet) and response_packet[offset] != 0:
                label_len = response_packet[offset]
                offset += 1 + label_len
            offset += 1  # Skip final 0
        
        # Skip TYPE, CLASS, TTL
        offset += 8
        
        # Skip RDLENGTH and RDATA
        if offset + 2 <= len(response_packet):
            rdlength = struct.unpack("!H", response_packet[offset:offset+2])[0]
            offset += 2 + rdlength
    
    # Parse additional records (looking for OPT record)
    for _ in range(arcount):
        if offset >= len(response_packet):
            return None, None
        
        # Check if this is an OPT record (NAME should be 0x00, TYPE should be 41)
        if (offset < len(response_packet) and 
            response_packet[offset] == 0 and  # ROOT name
            offset + 10 < len(response_packet)):
            
            # Parse OPT record
            offset += 1  # Skip ROOT name
            rtype, rclass, ttl = struct.unpack("!HHI", response_packet[offset:offset+8])
            offset += 8
            
            if rtype == 41:  # OPT record
                rdlength = struct.unpack("!H", response_packet[offset:offset+2])[0]
                offset += 2
                
                # Parse options within OPT record
                opt_end = offset + rdlength
                while offset < opt_end and offset + 4 <= len(response_packet):
                    opt_code, opt_len = struct.unpack("!HH", response_packet[offset:offset+4])
                    offset += 4
                    
                    if opt_code == 10 and offset + opt_len <= len(response_packet):  # DNS Cookie
                        opt_data = response_packet[offset:offset+opt_len]
                        client_cookie = opt_data[:8] if len(opt_data) >= 8 else None
                        server_cookie = opt_data[8:16] if len(opt_data) >= 16 else None
                        return client_cookie, server_cookie
                    
                    offset += opt_len
                
                return None, None
        else:
            # Skip non-OPT record
            # Skip NAME
            if response_packet[offset] & 0xC0:  # Compression
                offset += 2
            else:
                while offset < len(response_packet) and response_packet[offset] != 0:
                    label_len = response_packet[offset]
                    offset += 1 + label_len
                offset += 1
            
            # Skip TYPE, CLASS, TTL
            offset += 8
            
            # Skip RDATA
            if offset + 2 <= len(response_packet):
                rdlength = struct.unpack("!H", response_packet[offset:offset+2])[0]
                offset += 2 + rdlength
    
    return None, None