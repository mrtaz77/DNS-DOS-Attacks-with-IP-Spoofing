#!/usr/bin/env python3
"""
Test script for UDP Fragmented Flood attack simulation.
This script demonstrates how to use the FragmentedUDPFlood class for educational purposes.

WARNING: Only use this for authorized testing in controlled environments!
"""

import sys
import os
import logging
from colorama import Fore, Style, init

# Add the parent directory to Python path so we can import the attack module
# This allows the script to work when run from the tests/ directory
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

# Initialize colorama for cross-platform color support
init(autoreset=True)

try:
    from attack.udp_fragmented_flood import FragmentedUDPFlood
except ImportError as e:
    print(f"Error importing FragmentedUDPFlood: {e}")
    print("Make sure the attack directory contains udp_fragmented_flood.py")
    print(f"Current directory: {os.getcwd()}")
    print(f"Script directory: {current_dir}")
    print(f"Parent directory: {parent_dir}")
    print(f"Python path: {sys.path}")
    sys.exit(1)


def print_colored(message, color=Fore.WHITE, style=Style.NORMAL):
    """Print colored message with fallback."""
    try:
        print(f"{style}{color}{message}{Style.RESET_ALL}")
    except (ImportError, AttributeError):
        print(message)


def print_header(message):
    """Print header in cyan."""
    print_colored(message, Fore.CYAN, Style.BRIGHT)


def print_warning(message):
    """Print warning in yellow."""
    print_colored(message, Fore.YELLOW, Style.BRIGHT)


def print_error(message):
    """Print error in red."""
    print_colored(message, Fore.RED, Style.BRIGHT)


def print_success(message):
    """Print success in green."""
    print_colored(message, Fore.GREEN, Style.BRIGHT)


def print_info(message):
    """Print info in blue."""
    print_colored(message, Fore.BLUE, Style.NORMAL)


def main():
    print_header("=" * 60)
    print_header("UDP FRAGMENTED FLOOD ATTACK SIMULATOR")
    print_header("=" * 60)

    print_warning("⚠️  WARNING: This tool is for educational purposes only!")
    print_warning(
        "⚠️  Only use against systems you own or have explicit permission to test!"
    )
    print()

    print_info(
        "This attack sends large UDP packets that are fragmented at the IP layer."
    )
    print_info(
        "The target must reassemble fragments, consuming memory and processing power."
    )
    print_info("Fragments are sent out of order to maximize processing overhead.")
    print()

    # Default test configuration
    target_ip = "127.0.0.1"  # Localhost for safe testing
    target_port = 53  # DNS port
    duration = 10  # 10 seconds
    threads = 3  # 3 threads for testing

    print("Default configuration:")
    print(f"Target IP: {target_ip}")
    print(f"Target Port: {target_port}")
    print(f"Duration: {duration} seconds")
    print(f"Threads: {threads}")
    print()

    # Ask user if they want to customize
    customize = (
        input("Do you want to customize the attack parameters? (y/n): ").lower().strip()
    )

    if customize == "y":
        try:
            target_ip = (
                input(f"Enter target IP (default: {target_ip}): ").strip() or target_ip
            )
            target_port = int(
                input(f"Enter target port (default: {target_port}): ") or target_port
            )
            duration = int(
                input(f"Enter duration in seconds (default: {duration}): ") or duration
            )
            threads = int(
                input(f"Enter number of threads (default: {threads}): ") or threads
            )
        except ValueError:
            print_warning("Invalid input, using default values...")

    print()
    print_header("Attack Configuration:")
    print(f"Target: {target_ip}:{target_port}")
    print(f"Duration: {duration} seconds")
    print(f"Threads: {threads}")
    print()

    # Confirm before starting
    confirm = (
        input("Are you sure you want to start the attack? (yes/no): ").lower().strip()
    )
    if confirm != "yes":
        print_warning("Attack cancelled.")
        return

    # Check for administrator privileges
    try:
        import socket

        test_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        test_socket.close()
        print_success("✓ Administrator privileges detected")
    except PermissionError:
        print_error("\nERROR: Administrator privileges required!")
        print_warning(
            "Please run this script as administrator (Windows) or with sudo (Linux/Mac)"
        )
        print_warning("Raw sockets are required for IP fragmentation control")
        return
    except Exception as e:
        print_error(f"Socket test failed: {e}")
        return

    print()
    print_header("Initializing UDP Fragmented Flood attack...")
    print_warning("Press Ctrl+C to stop the attack early")
    print()

    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[
            logging.FileHandler("udp_fragmented_flood_test.log"),
            logging.StreamHandler(),
        ],
    )

    # Create and execute the attack
    try:
        attack = FragmentedUDPFlood(target_ip, target_port, duration, threads)
        attack.attack()
    except KeyboardInterrupt:
        print_warning("\nAttack stopped by user.")
    except Exception as e:
        print_error(f"Error during attack: {e}")
        logging.error(f"UDP Fragmented Flood attack failed: {e}")


if __name__ == "__main__":
    main()
