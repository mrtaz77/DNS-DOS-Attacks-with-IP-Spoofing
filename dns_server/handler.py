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
                 acl_rules=None, tsig_key=None):
        self.zone_file = zone_file
        self.zone = dns.zone.from_file(zone_file, relativize=False)
        self.lock = threading.Lock()
        logging.info("Loaded zone from %s", zone_file)
        self.cache = Cache()
        self.acl = ACL(**(acl_rules or {}))
        self.metrics = MetricsCollector()
        self.forwarder = forwarder
        if key_file:
            with open(key_file,'rb') as f:
                self.private_key = serialization.load_pem_private_key(f.read(), password=None)
            self._publish_dnskey()
        else:
            self.private_key = None
        if tsig_key:
            self.tsig = TSIGAuthenticator(tsig_key['name'], tsig_key['secret'])
        else:
            self.tsig = None

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
            # Parse message with TSIG validation if TSIG is configured
            if self.tsig:
                msg = dns.message.from_wire(wire, keyring=self.tsig.keyring)
                if not msg.tsig:
                    logging.warning("TSIG required but not provided")
                    return None, None
                # TSIG validation happens automatically during from_wire parsing
                if not msg.had_tsig:
                    logging.warning("TSIG validation failed")
                    return None, None
            else:
                msg = dns.message.from_wire(wire)
                
            q = msg.question[0]
            qtype = dns.rdatatype.to_text(q.rdtype)
            if msg.opcode() == dns.opcode.UPDATE:
                self.metrics.inc_updates()
                logging.info("Processing DNS UPDATE for %s", q.name)
                return None, self._do_update(msg)
            if qtype in ('AXFR','IXFR'):
                logging.info("Processing %s for zone %s", qtype, q.name)
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
                logging.info("Applying update message")
                for upd in msg.update:
                    for rd in upd:
                        node = self.zone.nodes.get(upd.name) or self.zone.node_factory()
                        self.zone.nodes[upd.name] = node
                        rrs = node.find_rdataset(upd.rdclass, upd.rdtype, upd.covers, True)
                        rrs.add(rd)
                self.zone.to_file(self.zone_file, relativize=False, want_origin=True)
                logging.info("Update applied and zone file %s written", self.zone_file)
                return True
            except Exception:
                logging.exception("Update failed, rolling back")
                self.zone = backup
                return False

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
