import threading, copy, time
import logging
import dns.message, dns.zone, dns.dnssec, dns.update, dns.resolver  # type: ignore
from cryptography.hazmat.primitives import serialization
from .utils.tsig import TSIGAuthenticator
from .utils.cache import Cache
from .utils.acl import ACL
from .utils.metrics import MetricsCollector

class DNSHandler:
    def __init__(self, zone_file, key_file=None, forwarder=None,
                 acl_rules=None, tsig_key=None, is_secondary=False,
                 primary_server=None, primary_port=None, refresh_interval=None):
        self.zone_file = zone_file
        self.zone = dns.zone.from_file(zone_file, relativize=False)
        self.lock = threading.Lock()
        self.is_secondary = is_secondary
        self.primary_server = primary_server
        self.primary_port = primary_port or 53
        self.refresh_interval = refresh_interval or 3600
        
        server_type = "secondary" if is_secondary else "primary"
        logging.info("Loaded zone from %s (running as %s)", zone_file, server_type)
        
        self.cache = Cache()
        self.acl = ACL(**(acl_rules or {}))
        self.metrics = MetricsCollector()
        self.forwarder = forwarder
        
        # Initialize TSIG first
        if tsig_key:
            self.tsig = TSIGAuthenticator(tsig_key["name"], tsig_key["secret"])
        else:
            self.tsig = None
            
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

    def handle(self, wire, addr):
        client_ip = addr[0] if addr else None
        logging.info("Received request from %s (%d bytes)", client_ip, len(wire or b""))
        self.metrics.inc_queries()
        if client_ip and not self.acl.check(client_ip):
            self.metrics.inc_errors()
            logging.warning("ACL denied request from %s", client_ip)
            return None, None
        try:
            # Parse message - TSIG validation only for sensitive operations
            msg = dns.message.from_wire(wire, keyring=self.tsig.keyring if self.tsig else None)
            
            q = msg.question[0]
            qtype = dns.rdatatype.to_text(q.rdtype)
            
            # Check if TSIG is required for this operation type
            requires_tsig = (msg.opcode() == dns.opcode.UPDATE or qtype in ('AXFR', 'IXFR'))
            
            if requires_tsig and self.tsig:
                if not msg.tsig:
                    logging.warning("TSIG required for %s but not provided", qtype)
                    return None, None
                # TSIG validation happens automatically during from_wire parsing
                if not msg.had_tsig:
                    logging.warning("TSIG validation failed for %s", qtype)
                    return None, None
                    
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
                    return None, self._do_update(msg)
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
                if self.tsig:
                    resp.use_tsig(self.tsig.keyring, keyname=self.tsig.key_name)
                return resp.to_wire(), None
            resp = self._do_query(msg)
            if self.tsig and resp:
                resp.use_tsig(self.tsig.keyring, keyname=self.tsig.key_name)
            logging.info("Answered query for %s %s", q.name, qtype)
            return resp.to_wire(), None
        except Exception:
            self.metrics.inc_errors()
            logging.exception("Error handling request")
            return None, None

    def _do_query(self, msg):
        resp = dns.message.make_response(msg)
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
            if self.forwarder:
                logging.info("Forwarding query %s %s to %s", q.name, dns.rdatatype.to_text(q.rdtype), self.forwarder)
                ans = dns.resolver.resolve(str(q.name), q.rdtype, nameservers=[self.forwarder])
                rr = ans.rrset
                resp.answer.append(rr)
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
    
    def _notify_secondaries(self):
        """Send NOTIFY messages to secondary servers (simplified)"""
        # In a real implementation, this would send DNS NOTIFY messages
        # For now, we just log that notification would be sent
        logging.info("NOTIFY would be sent to secondary servers")

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
        """Perform AXFR from primary and update local zone file"""
        if not self.is_secondary or not self.primary_server:
            return False
            
        try:
            import dns.query
            
            # Create AXFR request
            zone_name = self.zone.origin
            
            # Use TSIG if available
            if self.tsig:
                keyring = self.tsig.keyring
                keyname = self.tsig.key_name
                axfr_query = dns.message.make_query(zone_name, dns.rdatatype.AXFR)
                axfr_query.use_tsig(keyring, keyname=keyname)
            else:
                axfr_query = dns.message.make_query(zone_name, dns.rdatatype.AXFR)
            
            # Perform AXFR
            response = dns.query.tcp(axfr_query, self.primary_server, 
                                   port=self.primary_port, timeout=30)
            
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
                    logging.info("Zone file updated and reloaded from primary")
                
                return True
            else:
                logging.warning("AXFR response contained no data")
                return False
                
        except Exception as e:
            logging.error("Zone transfer failed: %s", e)
            return False

    def _forward_update_to_primary(self, msg):
        """Forward DNS UPDATE to primary server"""
        if not self.primary_server:
            logging.error("Cannot forward UPDATE: no primary server configured")
            return None
            
        try:
            logging.info("Secondary server forwarding DNS UPDATE for %s to primary %s:%d", 
                        msg.question[0].name if msg.question else "unknown", 
                        self.primary_server, self.primary_port)
            
            # Ensure TSIG is properly applied to forwarded message
            if self.tsig:
                msg.use_tsig(self.tsig.keyring, keyname=self.tsig.key_name)
            
            # Forward the UPDATE to primary with retries
            max_retries = 3
            for attempt in range(max_retries):
                try:
                    response = dns.query.tcp(msg, self.primary_server, 
                                           port=self.primary_port, timeout=15)
                    
                    if response.rcode() == dns.rcode.NOERROR:
                        logging.info("UPDATE successfully forwarded to primary (attempt %d)", attempt + 1)
                        # Trigger zone refresh after successful update
                        threading.Thread(target=self._perform_zone_transfer, daemon=True).start()
                        return response
                    else:
                        logging.warning("Primary rejected forwarded UPDATE: %s (attempt %d)", 
                                      dns.rcode.to_text(response.rcode()), attempt + 1)
                        return response
                        
                except (ConnectionError, OSError, EOFError) as e:
                    logging.warning("Connection error forwarding UPDATE (attempt %d): %s", attempt + 1, e)
                    if attempt == max_retries - 1:
                        raise
                    time.sleep(1)  # Brief delay before retry
                    
        except Exception as e:
            logging.error("Failed to forward UPDATE to primary after %d attempts: %s", max_retries, e)
            # Return SERVFAIL response
            resp = dns.message.make_response(msg)
            resp.set_rcode(dns.rcode.SERVFAIL)
            return resp
