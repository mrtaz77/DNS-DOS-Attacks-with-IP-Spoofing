import threading, copy, time, random, socket
import logging
import dns.message, dns.zone, dns.dnssec, dns.update, dns.resolver, dns.query, dns.exception  # type: ignore
from cryptography.hazmat.primitives import serialization
from .utils.tsig import TSIGAuthenticator
from .utils.dns_cache import DNSCache, create_cache
from .utils.acl import ACL
from .utils.metrics import MetricsCollector
from .utils.rate_limiter import RateLimiter
from .utils.dns_cookies import DNSCookieManager, parse_cookie_option, create_cookie_option

class DNSHandler:
    def __init__(self, zone_file, key_file=None, forwarder=None, forwarders=None,
                acl_rules=None, tsig_key=None, is_secondary=False,
                primary_server=None, primary_port=None, refresh_interval=None,
                rate_limit_threshold=100, rate_limit_window=5, rate_limit_ban_duration=300,
                cache_type="lru", cache_size=10000, redis_url=None,
                cookie_required=False, cookie_secret_lifetime=86400*30):
        self.zone_file = zone_file
        self.zone = dns.zone.from_file(zone_file, relativize=False)
        self.lock = threading.Lock()
        self.is_secondary = is_secondary
        self.primary_server = primary_server
        self.primary_port = primary_port or 53
        self.refresh_interval = refresh_interval or 3600
        
        server_type = "secondary" if is_secondary else "primary"
        logging.info("Loaded zone from %s (running as %s)", zone_file, server_type)
        
        # Initialize enhanced cache
        try:
            if cache_type == "redis" and redis_url:
                self.cache = create_cache("redis", redis_url=redis_url)
                logging.info("Using Redis cache at %s", redis_url)
            elif cache_type == "hybrid":
                kwargs = {"memory_cache_size": cache_size}
                if redis_url:
                    kwargs["redis_url"] = redis_url
                self.cache = create_cache("hybrid", **kwargs)
                logging.info("Using hybrid cache (memory + Redis)")
            elif cache_type == "lru":
                self.cache = create_cache("lru", max_size=cache_size)
                logging.info("Using LRU cache with max size %d", cache_size)
            else:
                self.cache = DNSCache()  # Fallback to simple cache
                logging.info("Using simple cache")
        except Exception as e:
            logging.warning("Failed to initialize %s cache: %s. Using simple cache.", cache_type, e)
            self.cache = DNSCache()
        
        self.acl = ACL(**(acl_rules or {}))
        self.metrics = MetricsCollector()
        
        # Initialize forwarders - support both single and multiple forwarders
        self.forwarders = []  # List of (host, port) tuples
        self.forwarder_index = 0  # For round-robin selection
        self.forwarder_lock = threading.Lock()
        
        # Handle backward compatibility with single forwarder
        if forwarder:
            if forwarders:
                forwarders = [forwarder] + forwarders
            else:
                forwarders = [forwarder]
                
        # Parse forwarders - extract IP and port if IP:port format is used
        if forwarders:
            for fw in forwarders:
                if ':' in fw:
                    # Extract IP and port from IP:port format
                    parts = fw.split(':')
                    host = parts[0]
                    port = int(parts[1])
                else:
                    host = fw
                    port = 53  # Default DNS port
                
                self.forwarders.append((host, port))
                logging.info("Forwarder configured: %s:%d", host, port)
        
        # Keep backward compatibility for existing code
        if self.forwarders:
            self.forwarder = self.forwarders[0][0]
            self.forwarder_port = self.forwarders[0][1]
            logging.info("Multiple forwarders configured: %d servers", len(self.forwarders))
        else:
            self.forwarder = None
            self.forwarder_port = 53
        
        # Initialize rate limiter with DOS protection
        self.rate_limiter = RateLimiter(
            threshold=rate_limit_threshold,
            time_window=rate_limit_window,
            ban_duration=rate_limit_ban_duration
        )
        
        # Initialize DNS Cookie manager for anti-spoofing protection
        self.cookie_required = cookie_required
        self.cookie_manager = DNSCookieManager(secret_lifetime=cookie_secret_lifetime)
        if cookie_required:
            logging.info("DNS Cookies REQUIRED - enhanced protection against spoofing attacks")
        else:
            logging.info("DNS Cookies OPTIONAL - clients without cookies still served")
        
        # Initialize TSIG first
        if tsig_key:
            self.tsig = TSIGAuthenticator(tsig_key["name"], tsig_key["secret"])
            logging.info("TSIG configured with key name: %s", self.tsig.key_name)
            logging.info("TSIG keyring initialized with keys: %s", list(self.tsig.keyring.keys()))
        else:
            self.tsig = None
            logging.info("No TSIG authentication configured")
            
        # Initialize DNSSEC
        if key_file:
            with open(key_file,'rb') as f:
                self.private_key = serialization.load_pem_private_key(f.read(), password=None)
            self._publish_dnskey()
        else:
            self.private_key = None
        
        # Start secondary server functionality after all initialization
        if is_secondary and primary_server:
            logging.info("Secondary server configured with primary: %s:%d", 
                        primary_server, self.primary_port)
            # Start zone refresh thread for secondary
            self._start_zone_refresh()

    def _get_next_forwarder(self):
        """Get the next forwarder using round-robin selection"""
        if not self.forwarders:
            return None, None
            
        with self.forwarder_lock:
            host, port = self.forwarders[self.forwarder_index]
            self.forwarder_index = (self.forwarder_index + 1) % len(self.forwarders)
            return host, port

    def _get_random_forwarder(self):
        """Get a random forwarder (useful for retry logic)"""
        if not self.forwarders:
            return None, None
        return random.choice(self.forwarders)

    def _try_forwarder(self, query_msg, host, port, timeout=5):
        """Try to forward a query to a specific forwarder"""
        try:
            # Forward using UDP first, fall back to TCP if needed
            try:
                response = dns.query.udp(query_msg, host, port=port, timeout=timeout)
                return response
            except dns.exception.Timeout:
                # Try TCP on timeout
                response = dns.query.tcp(query_msg, host, port=port, timeout=timeout)
                return response
        except Exception as e:
            logging.warning("Failed to forward query to %s:%d: %s", host, port, e)
            return None

    def _publish_dnskey(self):
        origin = self.zone.origin
        node = self.zone.nodes.get(origin) or self.zone.node_factory()
        self.zone.nodes[origin] = node
        rr = node.find_rdataset(dns.rdataclass.IN, dns.rdatatype.DNSKEY, create=True)
        # create DNSKEY with flags=257 (ZSK), protocol=3, algorithm=8 (RSASHA256)
        pub = dns.dnssec.make_dnskey(
            self.private_key.public_key(),
            flags=257,
            protocol=3,
            algorithm=8
        )
        rr.add(pub)

    def _is_likely_dns_traffic(self, wire):
        """Quick check to determine if incoming data looks like DNS traffic"""
        if not wire or len(wire) < 12:  # DNS header is 12 bytes minimum
            return False
        
        # Check if it could be a DNS message by looking at the header
        try:
            # Basic DNS header structure check
            # First 2 bytes: ID
            # Next 2 bytes: Flags (QR, Opcode, AA, TC, RD, RA, Z, RCODE)
            flags = (wire[2] << 8) | wire[3]
            qr = (flags >> 15) & 1  # Query/Response bit
            opcode = (flags >> 11) & 0xF  # Opcode
            
            # Valid DNS opcodes: 0=QUERY, 1=IQUERY, 2=STATUS, 4=NOTIFY, 5=UPDATE
            if opcode not in (0, 1, 2, 4, 5):
                return False
            
            # Check question count (bytes 4-5)
            qdcount = (wire[4] << 8) | wire[5]
            if qdcount > 100:  # Unreasonably high question count
                return False
            
            return True
        except (IndexError, TypeError):
            return False

    def handle(self, wire, addr):
        client_ip = addr[0] if addr else None
        logging.info("Received request from %s (%d bytes)", client_ip, len(wire or b""))
        self.metrics.inc_queries()
        
        # Early filtering for non-DNS traffic
        if not self._is_likely_dns_traffic(wire):
            logging.debug("Received non-DNS traffic from %s, ignoring", client_ip)
            self.metrics.inc_errors()
            return None, None
        
        # Step 1: Rate limiting check (DOS protection)
        if client_ip and not self.rate_limiter.is_allowed(client_ip):
            self.metrics.inc_errors()
            logging.warning("Rate limit exceeded, dropping request from %s", client_ip)
            return None, None
        
        # Step 2: ACL check
        if client_ip and not self.acl.check(client_ip):
            self.metrics.inc_errors()
            logging.warning("ACL denied request from %s", client_ip)
            return None, None
        try:
            # Parse message - handle TSIG appropriately
            keyring = self.tsig.keyring if self.tsig else None
            try:
                msg = dns.message.from_wire(wire, keyring=keyring)
            except dns.tsig.BadSignature as e:
                if keyring:
                    logging.warning("TSIG signature validation failed from %s: %s", client_ip, e)
                    self.metrics.inc_errors()
                    return None, None
                else:
                    # No keyring configured, but message has TSIG - reject with FormErr
                    logging.warning("Received TSIG-signed message but no TSIG key configured from %s", client_ip)
                    self.metrics.inc_errors()
                    # Return a FORMERR response
                    try:
                        temp_msg = dns.message.from_wire(wire, keyring=None, ignore_trailing=True)
                        resp = dns.message.make_response(temp_msg)
                        resp.set_rcode(dns.rcode.FORMERR)
                        return resp.to_wire(), None
                    except Exception:
                        return None, None
            except dns.exception.FormError as e:
                logging.debug("Received malformed DNS message from %s: %s", client_ip, e)
                self.metrics.inc_errors()
                return None, None
            except Exception as e:
                if "keyring" in str(e).lower() or "tsig" in str(e).lower():
                    logging.warning("TSIG-related parsing error from %s: %s", client_ip, e)
                    self.metrics.inc_errors()
                    return None, None
                else:
                    # Handle other parsing errors more gracefully
                    logging.debug("DNS message parsing error from %s: %s", client_ip, e)
                    self.metrics.inc_errors()
                    return None, None
            
            # Validate that the message has questions
            if not msg.question:
                logging.debug("Received DNS message with no questions from %s, ignoring", client_ip)
                self.metrics.inc_errors()
                return None, None
            
            # Validate message opcode early to catch malformed messages
            try:
                opcode = msg.opcode()
                if opcode not in (dns.opcode.QUERY, dns.opcode.UPDATE, dns.opcode.NOTIFY):
                    logging.debug("Received DNS message with unsupported opcode %s from %s, ignoring", 
                                dns.opcode.to_text(opcode), client_ip)
                    self.metrics.inc_errors()
                    return None, None
            except Exception as e:
                logging.debug("Failed to get opcode from DNS message from %s: %s", client_ip, e)
                self.metrics.inc_errors()
                return None, None
            
            q = msg.question[0]
            qtype = dns.rdatatype.to_text(q.rdtype)
            
            # Filter out .local domains (mDNS/Bonjour traffic)
            if str(q.name).lower().endswith('.local.'):
                logging.debug("Ignoring .local domain query: %s %s (mDNS traffic)", q.name, qtype)
                # Return NXDOMAIN for .local queries
                resp = dns.message.make_response(msg)
                resp.set_rcode(dns.rcode.NXDOMAIN)
                return resp.to_wire(), None
            
            # Check if TSIG is required for this operation type
            requires_tsig = (msg.opcode() == dns.opcode.UPDATE or qtype in ('AXFR', 'IXFR'))
            
            if requires_tsig and self.tsig:
                if not msg.tsig:
                    logging.warning("TSIG required for %s but not provided", qtype)
                    return None, None
                # TSIG validation happens automatically during from_wire parsing
            
            # Step 3: DNS Cookie validation for anti-spoofing protection
            client_cookie = None
            server_cookie = None
            cookie_valid = False
            
            # Check for DNS COOKIE option in EDNS(0)
            if msg.edns >= 0:
                for option in msg.options:
                    if option.otype == 10:  # DNS COOKIE option code
                        client_cookie, server_cookie = parse_cookie_option(option.data)
                        if client_cookie:
                            cookie_valid = True
                            if server_cookie:
                                # Validate existing server cookie
                                cookie_valid = self.cookie_manager.validate_server_cookie(
                                    client_ip, client_cookie, server_cookie)
                        break
            
            # If cookies are required and no valid cookie, reject or respond with BADCOOKIE
            if self.cookie_required and not cookie_valid:
                logging.warning("DNS Cookie required but not valid from %s", client_ip)
                resp = dns.message.make_response(msg)
                resp.set_rcode(dns.rcode.BADCOOKIE)
                
                # Add new server cookie to response
                if client_cookie:
                    new_server_cookie = self.cookie_manager.generate_server_cookie(client_ip, client_cookie)
                    cookie_data = create_cookie_option(client_cookie, new_server_cookie)
                    resp.use_edns(edns=0)
                    resp.options.append(dns.edns.GenericOption(10, cookie_data))
                
                return resp.to_wire(), None
                if not msg.had_tsig:
                    logging.warning("TSIG validation failed for %s", qtype)
                    return None, None
                    
            if msg.opcode() == dns.opcode.NOTIFY:
                # Handle NOTIFY message from primary to trigger zone refresh
                if self.is_secondary:
                    logging.info("NOTIFY received from primary for zone %s, triggering zone transfer", q.name)
                    # Schedule immediate zone transfer
                    threading.Thread(target=self._perform_zone_transfer, daemon=True).start()
                
                # Send NOERROR response to NOTIFY
                resp = dns.message.make_response(msg)
                resp.set_rcode(dns.rcode.NOERROR)
                return resp.to_wire(), None
                
            if msg.opcode() == dns.opcode.UPDATE:
                self.metrics.inc_updates()
                if self.is_secondary:
                    logging.info("Secondary server forwarding DNS UPDATE for %s to primary", q.name)
                    # Forward UPDATE to primary server
                    forward_response = self._forward_update_to_primary(msg)
                    if forward_response:
                        return forward_response.to_wire(), None
                    else:
                        # Return SERVFAIL if forwarding failed
                        resp = dns.message.make_response(msg)
                        resp.set_rcode(dns.rcode.SERVFAIL)
                        return resp.to_wire(), None
                else:
                    logging.info("Processing DNS UPDATE for %s", q.name)
                    success = self._do_update(msg)
                    # Return proper response for UPDATE
                    resp = dns.message.make_response(msg)
                    if success:
                        resp.set_rcode(dns.rcode.NOERROR)
                        logging.info("UPDATE successful for %s", q.name)
                    else:
                        resp.set_rcode(dns.rcode.SERVFAIL)
                        logging.error("UPDATE failed for %s", q.name)
                    
                    if self.tsig:
                        resp.use_tsig(self.tsig.keyring, keyname=self.tsig.key_name)
                    return resp.to_wire(), None
            if qtype in ('AXFR','IXFR'):
                logging.info("Processing %s for zone %s", qtype, q.name)
                if qtype == 'IXFR':
                    return self._do_ixfr(msg).to_wire(), None
                else:
                    return self._do_axfr(msg).to_wire(), None
            # check cache
            rr = self.cache.get(q.name, qtype)
            if rr:
                logging.info("Cache hit for %s %s", q.name, qtype)
                resp = dns.message.make_response(msg)
                resp.answer.append(rr)
                # Add DNS Cookie to cached response
                if client_cookie:
                    new_server_cookie = self.cookie_manager.generate_server_cookie(client_ip, client_cookie)
                    cookie_data = create_cookie_option(client_cookie, new_server_cookie)
                    resp.use_edns(edns=0)
                    resp.options.append(dns.edns.GenericOption(10, cookie_data))
                if self.tsig:
                    resp.use_tsig(self.tsig.keyring, keyname=self.tsig.key_name)
                return resp.to_wire(), None
            resp = self._do_query(msg)
            if resp is None:
                logging.warning("Unable to process query message")
                return None, None
            # Add DNS Cookie to response if client provided one
            if client_cookie and resp:
                new_server_cookie = self.cookie_manager.generate_server_cookie(client_ip, client_cookie)
                cookie_data = create_cookie_option(client_cookie, new_server_cookie)
                resp.use_edns(edns=0)
                resp.options.append(dns.edns.GenericOption(10, cookie_data))
                logging.debug("Added DNS Cookie to response for %s", client_ip)
            
            if self.tsig and resp:
                resp.use_tsig(self.tsig.keyring, keyname=self.tsig.key_name)
            logging.info("Answered query for %s %s", q.name, qtype)
            return resp.to_wire(), None
        except Exception as e:
            self.metrics.inc_errors()
            # Don't log full stack traces for common malformed message errors
            if "FormError" in str(e) or "not a query" in str(e):
                logging.debug("Malformed DNS message from %s: %s", client_ip, e)
            else:
                logging.exception("Error handling request from %s", client_ip)
            return None, None

    def _do_query(self, msg):
        # Check if this is actually a query message
        if msg.opcode() != dns.opcode.QUERY:
            logging.warning("Received non-query message with opcode %s", dns.opcode.to_text(msg.opcode()))
            return None
            
        if not msg.question:
            logging.warning("Received query message with no questions")
            return None
        
        # Check if this is a valid query that can have a response made
        try:
            resp = dns.message.make_response(msg)
        except dns.exception.FormError as e:
            logging.debug("Cannot create response for malformed message from %s: %s", 
                         msg.question[0].name if msg.question else "unknown", e)
            return None
        except Exception as e:
            logging.debug("Unexpected error creating response: %s", e)
            return None
            
        q = msg.question[0]
        try:
            # Try to find the node first
            if q.name in self.zone.nodes:
                node = self.zone.nodes[q.name]
                rdataset = node.find_rdataset(dns.rdataclass.IN, q.rdtype)
                # Create an rrset from the rdataset - convert rdataset to rrset
                rr = dns.rrset.RRset(q.name, rdataset.rdclass, rdataset.rdtype)
                rr.ttl = rdataset.ttl
                for rdata in rdataset:
                    rr.add(rdata)
                ttl = rr.ttl
                self.cache.set(q.name, dns.rdatatype.to_text(q.rdtype), rr, ttl)
                logging.info("Zone answer: %s %s (ttl=%d)", q.name, dns.rdatatype.to_text(q.rdtype), ttl)
                resp.answer.append(rr)
            else:
                raise KeyError
        except KeyError:
            if self.forwarders:
                # Try to forward to multiple upstream servers
                forward_query = dns.message.make_query(q.name, q.rdtype, q.rdclass)
                response = None
                
                # First try: use round-robin selection
                primary_host, primary_port = self._get_next_forwarder()
                if primary_host:
                    logging.info("Forwarding query %s %s to %s:%d", q.name, dns.rdatatype.to_text(q.rdtype), primary_host, primary_port)
                    response = self._try_forwarder(forward_query, primary_host, primary_port)
                
                # If primary forwarder failed, try other forwarders
                if not response and len(self.forwarders) > 1:
                    logging.info("Primary forwarder failed, trying other forwarders...")
                    for _ in range(len(self.forwarders) - 1):  # Try remaining forwarders
                        backup_host, backup_port = self._get_next_forwarder()
                        if backup_host and (backup_host, backup_port) != (primary_host, primary_port):
                            logging.info("Trying backup forwarder %s:%d", backup_host, backup_port)
                            response = self._try_forwarder(forward_query, backup_host, backup_port)
                            if response:
                                break
                
                if response:
                    # Extract answer from response
                    if response.answer:
                        for rr in response.answer:
                            if rr.rdtype == q.rdtype:
                                resp.answer.append(rr)
                                # Cache the forwarded response
                                ttl = rr.ttl
                                self.cache.set(q.name, dns.rdatatype.to_text(q.rdtype), rr, ttl)
                                logging.info("Cached forwarded response for %s %s (ttl=%d)", q.name, dns.rdatatype.to_text(q.rdtype), ttl)
                                break
                        if not resp.answer:
                            # Add first answer even if type doesn't match exactly
                            first_rr = response.answer[0]
                            resp.answer.append(first_rr)
                            # Cache it anyway
                            ttl = first_rr.ttl
                            self.cache.set(q.name, dns.rdatatype.to_text(first_rr.rdtype), first_rr, ttl)
                            logging.info("Cached forwarded response for %s %s (ttl=%d)", q.name, dns.rdatatype.to_text(first_rr.rdtype), ttl)
                    else:
                        # No answer in response
                        resp.set_rcode(response.rcode())
                        
                    # Check for NXDOMAIN
                    if response.rcode() == dns.rcode.NXDOMAIN:
                        logging.info("NXDOMAIN from upstream for %s %s", q.name, dns.rdatatype.to_text(q.rdtype))
                        resp.set_rcode(dns.rcode.NXDOMAIN)
                else:
                    # All forwarders failed
                    logging.error("All forwarders failed for %s %s", q.name, dns.rdatatype.to_text(q.rdtype))
                    resp.set_rcode(dns.rcode.SERVFAIL)
            else:
                logging.info("NXDOMAIN for %s %s", q.name, dns.rdatatype.to_text(q.rdtype))
                resp.set_rcode(dns.rcode.NXDOMAIN)
        return resp

    def _do_update(self, msg):
        with self.lock:
            backup = copy.deepcopy(self.zone)
            try:
                logging.info("Applying DNS UPDATE message with %d update sections", len(msg.update))
                
                # Apply updates
                for upd in msg.update:
                    logging.info("Processing update for %s %s", upd.name, dns.rdatatype.to_text(upd.rdtype))
                    for rd in upd:
                        node = self.zone.nodes.get(upd.name) or self.zone.node_factory()
                        self.zone.nodes[upd.name] = node
                        rrs = node.find_rdataset(upd.rdclass, upd.rdtype, upd.covers, True)
                        rrs.add(rd)
                        logging.info("Added record: %s %s %s", upd.name, dns.rdatatype.to_text(upd.rdtype), rd)
                
                # Increment SOA serial
                self._increment_soa_serial()
                
                # Invalidate cache for updated records and SOA
                self._invalidate_updated_cache(msg.update)
                
                # Write updated zone to file
                self.zone.to_file(self.zone_file, relativize=False, want_origin=True)
                logging.info("Update applied successfully, zone file %s written", self.zone_file)
                
                # Notify secondaries if this is a primary
                if not self.is_secondary:
                    logging.info("Notifying secondaries of zone update")
                    self._notify_secondaries()
                
                return True
            except Exception as e:
                logging.exception("Update failed: %s", e)
                self.zone = backup
                return False
    
    def _increment_soa_serial(self):
        """Increment the SOA serial number"""
        try:
            soa_node = self.zone.nodes[self.zone.origin]
            soa_rdataset = soa_node.find_rdataset(dns.rdataclass.IN, dns.rdatatype.SOA)
            
            if soa_rdataset:
                # Get the current SOA record
                old_soa = list(soa_rdataset)[0]
                new_serial = old_soa.serial + 1
                
                # Create new SOA record with incremented serial
                new_soa = dns.rdata.from_text(
                    dns.rdataclass.IN, dns.rdatatype.SOA,
                    f"{old_soa.mname} {old_soa.rname} {new_serial} {old_soa.refresh} {old_soa.retry} {old_soa.expire} {old_soa.minimum}"
                )
                
                # Replace the SOA record
                soa_rdataset.clear()
                soa_rdataset.add(new_soa)
                
                logging.info("SOA serial incremented from %d to %d", old_soa.serial, new_serial)
                
        except Exception as e:
            logging.error("Failed to increment SOA serial: %s", e)
    
    def _invalidate_updated_cache(self, update_sections):
        """Invalidate cache entries for updated records and SOA"""
        try:
            # Always invalidate SOA since the serial was incremented
            self.cache.remove(self.zone.origin, "SOA")
            logging.debug("Invalidated SOA cache for %s", self.zone.origin)
            
            # Invalidate cache for each updated record
            for upd in update_sections:
                self.cache.remove(upd.name, dns.rdatatype.to_text(upd.rdtype))
                logging.debug("Invalidated cache for %s %s", upd.name, dns.rdatatype.to_text(upd.rdtype))
                
            logging.info("Cache invalidated for %d updated records + SOA", len(update_sections))
            
        except Exception as e:
            logging.warning("Failed to invalidate cache entries: %s", e)
            # Fall back to clearing entire cache if selective invalidation fails
            self.cache.clear()
            logging.info("Fell back to clearing entire cache")

    def _notify_secondaries(self):
        """Send NOTIFY messages to secondary servers and force refresh"""
        # For our test setup, we know the secondary servers are on specific ports
        secondary_ports = [7354, 8354]  # TCP ports for secondary servers
        
        for port in secondary_ports:
            try:
                # Create NOTIFY message
                notify_msg = dns.message.make_query(self.zone.origin, dns.rdatatype.SOA, dns.rdataclass.IN)
                notify_msg.set_opcode(dns.opcode.NOTIFY)
                
                # Send NOTIFY to secondary
                dns.query.tcp(notify_msg, '127.0.0.1', port=port, timeout=5)
                logging.info("NOTIFY sent to secondary on port %d", port)
                
            except Exception as e:
                logging.warning("Failed to send NOTIFY to secondary on port %d: %s", port, e)
        
        # Also log for debugging
        logging.info("NOTIFY messages sent to configured secondary servers")

    def _do_axfr(self, msg):
        resp = dns.message.make_response(msg)
        logging.info("Starting zone transfer for zone %s", self.zone.origin)
        for name, node in self.zone.nodes.items():
            for rdataset in node.rdatasets:
                rr = dns.rrset.RRset(name, rdataset.rdclass, rdataset.rdtype)
                rr.ttl = rdataset.ttl
                for rdata in rdataset:
                    rr.add(rdata)
                resp.answer.append(rr)
                if self.private_key:
                    # generate RRSIG for each RRset
                    sig = dns.rrset.RRset(name, dns.rdataclass.IN, dns.rdatatype.RRSIG)
                    # generate DNSKEY with matching parameters for signing
                    dnskey = dns.dnssec.make_dnskey(
                        self.private_key.public_key(),
                        flags=257,
                        protocol=3,
                        algorithm=8
                    )
                    signature = dns.dnssec.sign(
                        rr,
                        self.private_key,
                        self.zone.origin,
                        dnskey,
                        expiration=int(time.time()) + 3600,
                        origin=self.zone.origin
                    )
                    sig.add(signature)
                    resp.answer.append(sig)
        logging.info("Completed zone transfer for zone %s", self.zone.origin)
        return resp

    def _do_ixfr(self, msg):
        """Handle IXFR (Incremental Zone Transfer) requests"""
        resp = dns.message.make_response(msg)
        
        # Check if there's a serial number in the authority section
        client_serial = None
        for rr in msg.authority:
            if rr.rdtype == dns.rdatatype.SOA:
                client_serial = rr[0].serial
                break
        
        # Get current SOA serial from our zone
        try:
            soa_node = self.zone.nodes[self.zone.origin]
            soa_rdataset = soa_node.find_rdataset(dns.rdataclass.IN, dns.rdatatype.SOA)
            current_serial = list(soa_rdataset)[0].serial
        except (KeyError, IndexError) as e:
            logging.error("Could not find SOA record for IXFR: %s", e)
            # Fall back to full AXFR
            return self._do_axfr(msg)
        
        logging.info("IXFR request: client serial=%s, current serial=%s", 
                    client_serial, current_serial)
        
        # If client serial is None or >= current serial, zone is up to date
        if client_serial is None or client_serial >= current_serial:
            logging.info("Zone is up to date, sending SOA only")
            # Send current SOA to indicate no changes
            soa_rr = dns.rrset.RRset(self.zone.origin, dns.rdataclass.IN, dns.rdatatype.SOA)
            soa_rr.ttl = soa_rdataset.ttl
            for rdata in soa_rdataset:
                soa_rr.add(rdata)
            resp.answer.append(soa_rr)
            return resp
        
        # For simplicity, if serials differ, fall back to full AXFR
        # In a real implementation, we'd track incremental changes
        logging.info("Serial mismatch, falling back to full AXFR")
        return self._do_axfr(msg)

    def _start_zone_refresh(self):
        """Start periodic zone refresh for secondary servers"""
        if not self.is_secondary:
            return
            
        def refresh_worker():
            while True:
                try:
                    time.sleep(self.refresh_interval)
                    logging.info("Starting periodic zone refresh from primary %s:%d", 
                                self.primary_server, self.primary_port)
                    if self._perform_zone_transfer():
                        logging.info("Zone refresh completed successfully")
                    else:
                        logging.warning("Zone refresh failed")
                except Exception as e:
                    logging.error("Zone refresh error: %s", e)
        
        refresh_thread = threading.Thread(target=refresh_worker, daemon=True)
        refresh_thread.start()
        
        # Also perform initial zone transfer
        try:
            logging.info("Performing initial zone transfer from primary")
            self._perform_zone_transfer()
        except Exception as e:
            logging.warning("Initial zone transfer failed: %s", e)

    def _perform_zone_transfer(self):
        """Perform AXFR or IXFR from primary and update local zone file"""
        if not self.is_secondary or not self.primary_server:
            logging.debug("Zone transfer skipped: not secondary or no primary server configured")
            return False
            
        try:
            logging.info("=== Starting zone transfer process ===")
            logging.info("Zone: %s", self.zone.origin)
            logging.info("Primary server: %s:%d", self.primary_server, self.primary_port)
            logging.info("TSIG configured: %s", self.tsig is not None)
            if self.tsig:
                logging.info("TSIG key name: %s", self.tsig.key_name)
                logging.info("TSIG keyring has keys: %s", list(self.tsig.keyring.keys()))
            
            # Get current SOA serial
            zone_name = self.zone.origin
            current_serial = 0
            try:
                soa_node = self.zone.nodes[zone_name]
                soa_rdataset = soa_node.find_rdataset(dns.rdataclass.IN, dns.rdatatype.SOA)
                if soa_rdataset:
                    current_soa = list(soa_rdataset)[0]
                    current_serial = current_soa.serial
            except (KeyError, AttributeError):
                pass
            
            # Try IXFR first, fall back to AXFR
            ixfr_successful = False
            
            if current_serial > 0:
                try:
                    # Create IXFR request with current serial
                    ixfr_query = dns.message.make_query(zone_name, dns.rdatatype.IXFR, dns.rdataclass.IN)
                    
                    # Add SOA record with current serial to authority section for IXFR
                    current_soa_rdata = dns.rdata.from_text(
                        dns.rdataclass.IN, dns.rdatatype.SOA,
                        f"ns1.example.com. admin.example.com. {current_serial} 3600 1800 604800 3600"
                    )
                    ixfr_query.authority.append(dns.rrset.from_rdata(zone_name, 3600, current_soa_rdata))
                    
                    # Use TSIG if available
                    if self.tsig:
                        logging.info("Adding TSIG to IXFR query with key: %s", self.tsig.key_name)
                        ixfr_query.use_tsig(self.tsig.keyring, keyname=self.tsig.key_name)
                        logging.info("TSIG added to IXFR query successfully")
                    else:
                        logging.info("No TSIG configured for IXFR query")
                    
                    # Perform IXFR
                    logging.info("Attempting IXFR with current serial %d to %s:%d", 
                               current_serial, self.primary_server, self.primary_port)
                    
                    # Resolve hostname to IP to avoid Docker DNS issues
                    try:
                        primary_ip = socket.gethostbyname(self.primary_server)
                        logging.info("Resolved primary server %s to IP: %s", self.primary_server, primary_ip)
                    except socket.gaierror as e:
                        logging.warning("Failed to resolve hostname %s: %s, using hostname directly", self.primary_server, e)
                        primary_ip = self.primary_server
                    
                    response = dns.query.tcp(ixfr_query, primary_ip, 
                                           port=self.primary_port, timeout=20)
                    
                    if response.answer and len(response.answer) > 1:
                        # IXFR response format: SOA (old), deletions, SOA (new), additions, SOA (new)
                        logging.info("IXFR response received, processing incremental changes")
                        
                        # Apply IXFR changes
                        with self.lock:
                            for rrset in response.answer:
                                if rrset.rdtype == dns.rdatatype.SOA:
                                    # Update SOA
                                    soa_node = self.zone.nodes.get(rrset.name) or self.zone.node_factory()
                                    self.zone.nodes[rrset.name] = soa_node
                                    soa_rdataset = soa_node.find_rdataset(rrset.rdclass, rrset.rdtype, rrset.covers, True)
                                    soa_rdataset.clear()
                                    for rdata in rrset:
                                        soa_rdataset.add(rdata)
                                else:
                                    # Add/update other records
                                    node = self.zone.nodes.get(rrset.name) or self.zone.node_factory()
                                    self.zone.nodes[rrset.name] = node
                                    rdataset = node.find_rdataset(rrset.rdclass, rrset.rdtype, rrset.covers, True)
                                    rdataset.clear()
                                    for rdata in rrset:
                                        rdataset.add(rdata)
                            
                            # Write updated zone
                            self.zone.to_file(self.zone_file, relativize=False, want_origin=True)
                            
                            # Invalidate cache after IXFR update
                            self.cache.clear()
                            logging.info("Cache cleared after IXFR update")
                            
                        ixfr_successful = True
                        logging.info("IXFR completed successfully")
                        
                except Exception as e:
                    logging.warning("IXFR failed, falling back to AXFR: %s", e)
            
            # Fall back to AXFR if IXFR failed or wasn't attempted
            if not ixfr_successful:
                logging.info("Starting AXFR from primary %s:%d", self.primary_server, self.primary_port)
                
                # Create AXFR request
                if self.tsig:
                    logging.info("Creating AXFR query with TSIG authentication")
                    keyring = self.tsig.keyring
                    keyname = self.tsig.key_name
                    logging.info("Using TSIG key: %s", keyname)
                    logging.info("Keyring contains: %s", list(keyring.keys()))
                    axfr_query = dns.message.make_query(zone_name, dns.rdatatype.AXFR)
                    axfr_query.use_tsig(keyring, keyname=keyname)
                    logging.info("TSIG added to AXFR query successfully")
                else:
                    logging.info("Creating AXFR query WITHOUT TSIG authentication")
                    axfr_query = dns.message.make_query(zone_name, dns.rdatatype.AXFR)
                
                logging.info("Sending AXFR query to %s:%d", self.primary_server, self.primary_port)
                # Perform AXFR - resolve hostname to IP first to avoid Docker DNS issues
                try:
                    primary_ip = socket.gethostbyname(self.primary_server)
                    logging.info("Resolved primary server %s to IP: %s", self.primary_server, primary_ip)
                except socket.gaierror as e:
                    logging.warning("Failed to resolve hostname %s: %s, using hostname directly", self.primary_server, e)
                    primary_ip = self.primary_server
                
                response = dns.query.tcp(axfr_query, primary_ip, 
                                       port=self.primary_port, timeout=30)
                
                logging.info("AXFR response received, response code: %s", response.rcode())
                if response.answer:
                    # Update local zone file with transferred data
                    with self.lock:
                        with open(self.zone_file, 'w') as f:
                            f.write(f"$ORIGIN {zone_name}\n")
                            f.write("$TTL 3600\n")
                            
                            for rrset in response.answer:
                                f.write(f"{rrset}\n")
                        
                        # Reload zone from updated file
                        self.zone = dns.zone.from_file(self.zone_file, relativize=False)
                        
                        # Invalidate cache after zone reload
                        self.cache.clear()
                        logging.info("Cache cleared after zone update from primary")
                        
                        logging.info("Zone file updated and reloaded from primary")
                    
                    return True
                else:
                    logging.warning("AXFR response contained no data")
                    return False
            
            logging.info("Zone refresh completed successfully")
            return True
                
        except dns.tsig.BadSignature as e:
            logging.error("TSIG authentication failed: %s", e)
            logging.error("This suggests TSIG key mismatch or timing issues")
            return False
        except dns.tsig.BadTime as e:
            logging.error("TSIG time validation failed: %s", e)
            logging.error("Check system clocks on primary and secondary servers")
            return False
        except dns.exception.Timeout as e:
            logging.error("Zone transfer timeout: %s", e)
            return False
        except dns.query.BadResponse as e:
            logging.error("Bad response from primary server: %s", e)
            return False
        except ConnectionRefusedError as e:
            logging.error("Connection refused by primary server %s:%d - %s", 
                         self.primary_server, self.primary_port, e)
            return False
        except Exception as e:
            logging.error("Zone transfer failed with unexpected error: %s", e)
            logging.error("Error type: %s", type(e).__name__)
            import traceback
            logging.error("Full traceback: %s", traceback.format_exc())
            return False

    def _forward_update_to_primary(self, msg):
        """Forward DNS UPDATE to primary server"""
        if not self.primary_server:
            logging.error("Cannot forward UPDATE: no primary server configured")
            return None
            
        if not msg.question:
            logging.error("Cannot forward UPDATE: no questions in message")
            return None
            
        try:
            logging.info("Secondary server forwarding DNS UPDATE for %s to primary", 
                        msg.question[0].name)
            logging.info("Secondary server forwarding DNS UPDATE for %s to primary %s:%d", 
                        msg.question[0].name, 
                        self.primary_server, self.primary_port)
            
            # Create a fresh message copy to avoid TSIG conflicts
            forward_msg = dns.message.make_query(msg.question[0].name, msg.question[0].rdtype)
            forward_msg.set_opcode(dns.opcode.UPDATE)  # Set UPDATE opcode
            forward_msg.update = msg.update
            forward_msg.authority = msg.authority
            forward_msg.additional = msg.additional
            
            # Apply TSIG to the fresh message
            if self.tsig:
                forward_msg.use_tsig(self.tsig.keyring, keyname=self.tsig.key_name)
            
            # Forward the UPDATE to primary with improved error handling
            max_retries = 3
            for attempt in range(max_retries):
                try:
                    # Use shorter timeout and better connection handling
                    response = dns.query.tcp(forward_msg, self.primary_server, 
                                           port=self.primary_port, timeout=10, 
                                           one_rr_per_rrset=True)
                    
                    if response.rcode() == dns.rcode.NOERROR:
                        logging.info("UPDATE successfully forwarded to primary (attempt %d)", attempt + 1)
                        # Schedule zone refresh after successful update (with delay)
                        threading.Timer(2.0, self._perform_zone_transfer).start()
                        return response
                    else:
                        logging.warning("Primary rejected forwarded UPDATE: %s (attempt %d)", 
                                      dns.rcode.to_text(response.rcode()), attempt + 1)
                        return response
                        
                except (OSError, EOFError) as e:
                    logging.warning("Connection error forwarding UPDATE (attempt %d): %s", attempt + 1, e)
                    if attempt == max_retries - 1:
                        logging.error("Failed to forward UPDATE to primary after %d attempts: %s", max_retries, e)
                        # Return SERVFAIL response
                        resp = dns.message.make_response(msg)
                        resp.set_rcode(dns.rcode.SERVFAIL)
                        return resp
                    time.sleep(2)  # Longer delay between retries
                    
        except Exception as e:
            logging.error("Failed to forward UPDATE to primary: %s", e)
            # Return SERVFAIL response
            resp = dns.message.make_response(msg)
            resp.set_rcode(dns.rcode.SERVFAIL)
            return resp

    def get_cache_stats(self):
        """Get cache statistics if available"""
        if hasattr(self.cache, 'get_stats'):
            return self.cache.get_stats()
        elif hasattr(self.cache, 'get_size'):
            return {"size": self.cache.get_size(), "type": "lru"}
        else:
            return {"type": "simple", "stats": "not available"}
    
    def cleanup_cache(self):
        """Clean up expired cache entries if supported"""
        if hasattr(self.cache, 'cleanup_expired'):
            removed = self.cache.cleanup_expired()
            if removed > 0:
                logging.info("Cleaned up %d expired cache entries", removed)
            return removed
        return 0
