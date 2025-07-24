import argparse
from pathlib import Path


class ClientConfig:
    """Configuration handler for DNS client"""

    def __init__(self):
        self.server = None
        self.port = 53
        self.zone = None
        self.interval = 1.0
        self.timeout = 5.0
        self.use_tcp = False
        self.log = './client.log'

    @classmethod
    def from_args(cls):
        """Create configuration from command line arguments"""
        parser = argparse.ArgumentParser(
            description="🌐 DNS Client using raw DNS packets"
        )
        parser.add_argument("--server", required=True, help="DNS server IP")
        parser.add_argument("--port", type=int, default=53, help="DNS server port")
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

        args = parser.parse_args()

        config = cls()
        config.server = args.server
        config.port = args.port
        config.zone = args.zone
        config.interval = args.interval
        config.timeout = args.timeout
        config.use_tcp = args.use_tcp
        config.log = args.log

        return config

    def validate(self):
        """Validate configuration"""
        if not self.server:
            raise ValueError("Server is required")

        if self.port < 1 or self.port > 65535:
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
