import argparse
from pathlib import Path


class ClientConfig:
    """Configuration handler for DNS client"""

    def __init__(self):
        self.server_ip = None
        self.server_port = 53
        self.zone = None
        self.interval = 1.0
        self.timeout = 5.0
        self.use_tcp = False
        self.log = "./client.log"
        self.bind_ip = None
        self.bind_port = None
        self.report_dir = None
        self.use_cookies = False
        self.duration = 30  # default duration in seconds

    @classmethod
    def from_args(cls):
        """Create configuration from command line arguments"""
        parser = argparse.ArgumentParser(
            description="🌐 DNS Client using raw DNS packets"
        )
        parser.add_argument("--server-ip", required=True, help="DNS server IP")
        parser.add_argument(
            "--server-port", type=int, default=53, help="DNS server port"
        )
        parser.add_argument("--zone", help="Path to zone file (optional)")
        parser.add_argument(
            "--interval",
            type=float,
            default=1.0,
            help="Interval between queries (seconds)",
        )
        parser.add_argument(
            "--timeout", type=float, default=5.0, help="Query timeout (seconds)"
        )
        parser.add_argument(
            "--use-tcp", action="store_true", help="Use TCP instead of UDP"
        )
        parser.add_argument(
            "--log", type=str, default="./client.log", help="Log file path"
        )
        parser.add_argument(
            "--bind-ip",
            type=str,
            default="127.0.0.1",
            help="Source IP to bind for outgoing DNS requests",
        )
        parser.add_argument(
            "--bind-port",
            type=int,
            default=5353,
            help="Source port to bind for outgoing DNS requests",
        )
        parser.add_argument(
            "--report-dir",
            type=str,
            default="simulation/client/analysis",
            help="Directory to save plots and metrics reports",
        )
        parser.add_argument(
            "--use-cookies",
            action="store_true",
            help="Use DNS Cookies (RFC 7873) for enhanced security",
        )
        parser.add_argument(
            "--duration",
            type=float,
            default=30,
            help="How long to run the client (seconds, default: 30)",
        )

        args = parser.parse_args()

        config = cls()
        config.server_ip = args.server_ip
        config.server_port = args.server_port
        config.zone = args.zone
        config.interval = args.interval
        config.timeout = args.timeout
        config.use_tcp = args.use_tcp
        config.log = args.log
        config.bind_ip = args.bind_ip
        config.bind_port = args.bind_port
        config.report_dir = args.report_dir
        config.use_cookies = args.use_cookies
        config.duration = args.duration

        # Ensure log file directory exists
        log_path = Path(config.log)
        if log_path.parent and not log_path.parent.exists():
            log_path.parent.mkdir(parents=True, exist_ok=True)
        config.log = str(log_path)

        # Ensure report directory exists
        report_path = Path(config.report_dir)
        if not report_path.exists():
            report_path.mkdir(parents=True, exist_ok=True)
        config.report_dir = str(report_path)

        return config

    def validate(self):
        """Validate configuration"""
        if not self.server_ip:
            raise ValueError("Server is required")

        if self.server_port < 1 or self.server_port > 65535:
            raise ValueError("Port must be between 1 and 65535")

        if self.interval <= 0:
            raise ValueError("Interval must be positive")

        if self.timeout <= 0:
            raise ValueError("Timeout must be positive")

        if self.zone and not Path(self.zone).exists():
            raise FileNotFoundError(f"Zone file not found: {self.zone}")

    @property
    def protocol(self):
        """Get protocol string"""
        return "TCP" if self.use_tcp else "UDP"
