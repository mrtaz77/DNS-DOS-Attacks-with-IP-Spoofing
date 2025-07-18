import argparse
import threading
import time
import logging

from .handler import DNSHandler
from .servers.udp_server import UDPServer
from .servers.tcp_server import TCPServer
from .servers.tls_server import TLSServer
from .servers.doh_server import DoHServer


# configure root logger
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")


def main():
    parser = argparse.ArgumentParser(description="DNS Server")
    parser.add_argument("--zone", default="dns_server/zones/primary.zone", help="Path to zone file")
    parser.add_argument("--keyfile", help="Private key PEM file for DNSSEC signing (optional)")
    parser.add_argument("--tsig-name", help="TSIG key name (optional)")
    parser.add_argument("--tsig-secret", help="TSIG base64 secret (optional)")
    parser.add_argument("--forwarder", help="Upstream DNS forwarder IP or IP:port (default port 53)")
    parser.add_argument("--allow", nargs="*", default=[], help="ACL allow networks (CIDR)")
    parser.add_argument("--deny", nargs="*", default=[], help="ACL deny networks (CIDR)")
    parser.add_argument("--certfile", help="TLS certificate PEM for DoT/DoH (optional)")
    parser.add_argument("--certkey", help="TLS private key PEM for DoT/DoH (optional)")
    parser.add_argument("--addr", default="0.0.0.0", help="Bind address")
    parser.add_argument("--port-udp", type=int, default=53, help="UDP port for DNS queries")
    parser.add_argument("--port-tcp", type=int, default=53, help="TCP port for DNS queries")
    parser.add_argument("--port-dot", type=int, default=853, help="Port for DNS-over-TLS (DoT)")
    parser.add_argument("--port-doh", type=int, default=443, help="Port for DNS-over-HTTPS (DoH)")
    parser.add_argument("--secondary", action="store_true", help="Run as secondary server (read-only, no updates)")
    parser.add_argument("--primary-server", help="Primary server IP for zone transfers (required for secondary)")
    parser.add_argument("--primary-port", type=int, default=53, help="Primary server TCP port for zone transfers")
    parser.add_argument("--refresh-interval", type=int, default=3600, help="Zone refresh interval in seconds (for secondary)")
    
    # Rate limiting and DOS protection arguments
    parser.add_argument("--rate-limit-threshold", type=int, default=100, help="Maximum queries per IP in time window")
    parser.add_argument("--rate-limit-window", type=int, default=5, help="Rate limit time window in seconds")
    parser.add_argument("--rate-limit-ban-duration", type=int, default=300, help="IP ban duration in seconds")
    
    # Cache configuration arguments
    parser.add_argument("--cache-type", choices=["simple", "lru", "redis", "hybrid"], default="lru", 
                       help="Cache type: simple (no limit), lru (in-memory), redis (persistent), hybrid (memory+redis)")
    parser.add_argument("--cache-size", type=int, default=10000, help="Maximum cache entries for LRU/hybrid cache")
    parser.add_argument("--redis-url", help="Redis URL for redis/hybrid cache (default: redis://localhost:6379/0)")
    
    args = parser.parse_args()

    tsig = None
    if args.tsig_name and args.tsig_secret:
        tsig = {"name": args.tsig_name, "secret": args.tsig_secret}

    handler = DNSHandler(
        zone_file=args.zone,
        key_file=args.keyfile,
        forwarder=args.forwarder,
        acl_rules={"allow": args.allow, "deny": args.deny},
        tsig_key=tsig,
        is_secondary=args.secondary,
        primary_server=args.primary_server if args.secondary else None,
        primary_port=args.primary_port if args.secondary else None,
        refresh_interval=args.refresh_interval if args.secondary else None,
        rate_limit_threshold=args.rate_limit_threshold,
        rate_limit_window=args.rate_limit_window,
        rate_limit_ban_duration=args.rate_limit_ban_duration,
        cache_type=args.cache_type,
        cache_size=args.cache_size,
        redis_url=args.redis_url
    )

    threads = []
    # UDP server
    udp = UDPServer(handler, args.addr, args.port_udp)
    threads.append(threading.Thread(target=udp.serve, daemon=True))

    # TCP server
    tcp = TCPServer(handler, args.addr, args.port_tcp)
    threads.append(threading.Thread(target=tcp.serve, daemon=True))

    # TLS (DoT) and HTTPS (DoH) servers if certs provided
    if args.certfile and args.certkey:
        dot = TLSServer(handler, args.addr, args.port_dot, args.certfile, args.certkey)
        threads.append(threading.Thread(target=dot.serve, daemon=True))

        doh = DoHServer(handler, args.addr, args.port_doh, args.certfile, args.certkey)
        threads.append(threading.Thread(target=doh.serve, daemon=True))

    # start all
    for t in threads:
        t.start()

    logging.info("DNS servers running. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("Shutting down DNS servers.")


if __name__ == "__main__":
    main()
