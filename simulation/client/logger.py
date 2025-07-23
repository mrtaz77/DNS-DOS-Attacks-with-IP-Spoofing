import logging
from rich.console import Console
from rich.logging import RichHandler

# Global console instance
console = Console()


class ClientLogger:
    """Centralized logging setup for DNS client"""

    def __init__(self, log_file="client.log"):
        self.log_file = log_file
        self.file_logger = None
        self.console_logger = None
        self._setup_logging()

    def _setup_logging(self):
        """Setup both file and console logging"""
        # Create file logger
        self.file_logger = logging.getLogger("CLIENT")
        self.file_logger.setLevel(logging.DEBUG)

        # Create file handler
        file_handler = logging.FileHandler(self.log_file, mode="w")
        file_formatter = logging.Formatter(
            "[%(asctime)s] %(name)s - %(levelname)s - %(message)s"
        )
        file_handler.setFormatter(file_formatter)
        self.file_logger.addHandler(file_handler)

        # Setup console logging with Rich
        logging.basicConfig(
            level=logging.INFO,
            format="%(message)s",
            datefmt="[%X]",
            handlers=[
                RichHandler(console=console, rich_tracebacks=True),
            ],
        )

        self.console_logger = logging.getLogger("CLIENT")

    def get_file_logger(self):
        """Get file logger instance"""
        return self.file_logger

    def get_console_logger(self):
        """Get console logger instance"""
        return self.console_logger
