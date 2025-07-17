#!/usr/bin/env python3
"""
Test script for DNS Random Subdomain Query Flood attack simulation.
This script demonstrates how to use the DNSRandomSubdomainQueryFlood class for educational purposes.

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
    from attack.dns_random_subdomain_query_flood import DNSRandomSubdomainQueryFlood
except ImportError as e:
    print(f"Error importing DNSRandomSubdomainQueryFlood: {e}")
    print("Make sure the attack directory contains dns_random_subdomain_query_flood.py")
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


def display_attack_info():
    """Display detailed information about the DNS attack."""
    print_header("DNS RANDOM SUBDOMAIN QUERY FLOOD ATTACK")
    print_info("=" * 50)
    print_info("This attack exploits DNS servers by:")
    print_info("• Generating random, non-existent subdomain queries")
    print_info("• Forcing DNS cache misses and expensive lookups")
    print_info("• Using IP spoofing to appear as distributed requests")
    print_info("• Overwhelming DNS server processing and memory")
    print()
    print_info("Attack Features:")
    print_info("🎭 IP Spoofing: Random source IP for each query")
    print_info("🎲 Random Subdomains: abc123.example.com, xyz789.google.com")
    print_info("💥 Multiple Query Types: A, AAAA, MX, CNAME, NS, TXT")
    print_info("🔄 Cache Bypass: Random domains ensure no cache hits")
    print_info("⚡ Processing Overhead: Forces recursive lookups or NXDOMAIN")
    print()


def get_custom_domains():
    """Get custom base domains from user."""
    print_info("Enter custom base domains (press Enter with empty line to finish):")
    print_info("Example: example.com, google.com, github.com")

    domains = []
    while True:
        domain = input(f"Domain {len(domains) + 1} (or Enter to finish): ").strip()
        if not domain:
            break
        if "." in domain and len(domain) > 3:
            domains.append(domain)
        else:
            print_warning("Invalid domain format, please try again")

    return domains if domains else None


def get_custom_query_types():
    """Get custom query types from user."""
    print_info("Available DNS Query Types:")
    query_types_info = {
        1: "A (IPv4 address)",
        28: "AAAA (IPv6 address)",
        15: "MX (Mail Exchange)",
        5: "CNAME (Canonical Name)",
        2: "NS (Name Server)",
        16: "TXT (Text record)",
        6: "SOA (Start of Authority)",
        12: "PTR (Pointer record)",
    }

    for qtype, desc in query_types_info.items():
        print_info(f"  {qtype}: {desc}")

    print_info("Enter query type numbers separated by commas (e.g., 1,28,15):")

    try:
        user_input = input("Query types (or Enter for default): ").strip()
        if not user_input:
            return None

        query_types = [int(x.strip()) for x in user_input.split(",")]
        valid_types = [qt for qt in query_types if qt in query_types_info]

        if valid_types:
            print_success(f"Selected query types: {valid_types}")
            return valid_types
        else:
            print_warning("No valid query types selected, using defaults")
            return None

    except ValueError:
        print_warning("Invalid input format, using default query types")
        return None


def get_default_config():
    """Get default attack configuration."""
    return {
        "target_ip": "127.0.0.1",
        "target_port": 53,
        "duration": 10,
        "threads": 5,
        "base_domains": None,
        "query_types": None,
    }


def display_default_config(config):
    """Display the default configuration."""
    print_header("Default Configuration:")
    print(f"Target IP: {config['target_ip']}")
    print(f"Target Port: {config['target_port']}")
    print(f"Duration: {config['duration']} seconds")
    print(f"Threads: {config['threads']}")
    print("Base Domains: Default set (example.com, google.com, etc.)")
    print("Query Types: Default set (A, AAAA, MX, CNAME, NS, TXT)")
    print()


def customize_basic_params(config):
    """Customize basic attack parameters."""
    try:
        config["target_ip"] = (
            input(f"Enter target IP (default: {config['target_ip']}): ").strip()
            or config["target_ip"]
        )
        config["target_port"] = int(
            input(f"Enter target port (default: {config['target_port']}): ")
            or config["target_port"]
        )
        config["duration"] = int(
            input(f"Enter duration in seconds (default: {config['duration']}): ")
            or config["duration"]
        )
        config["threads"] = int(
            input(f"Enter number of threads (default: {config['threads']}): ")
            or config["threads"]
        )
    except ValueError:
        print_warning("Invalid input, using default values...")


def customize_advanced_params(config):
    """Customize advanced attack parameters."""
    advanced = (
        input("Configure advanced options (domains, query types)? (y/n): ")
        .lower()
        .strip()
    )
    if advanced == "y":
        print()
        print_info("Configuring base domains...")
        config["base_domains"] = get_custom_domains()

        print()
        print_info("Configuring query types...")
        config["query_types"] = get_custom_query_types()


def display_final_config(config):
    """Display the final attack configuration."""
    print_header("Final Attack Configuration:")
    print(f"Target: {config['target_ip']}:{config['target_port']}")
    print(f"Duration: {config['duration']} seconds")
    print(f"Threads: {config['threads']}")
    if config["base_domains"]:
        print(f"Custom Domains: {config['base_domains']}")
    else:
        print("Base Domains: Using default set")
    if config["query_types"]:
        print(f"Query Types: {config['query_types']}")
    else:
        print("Query Types: Using default set")
    print()


def check_admin_privileges():
    """Check for administrator privileges required for raw sockets."""
    try:
        import socket

        test_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        test_socket.close()
        print_success("✓ Administrator privileges detected")
        return True
    except PermissionError:
        print_error("\nERROR: Administrator privileges required!")
        print_warning(
            "Please run this script as administrator (Windows) or with sudo (Linux/Mac)"
        )
        print_warning("Raw sockets are required for IP spoofing in DNS queries")
        return False
    except Exception as e:
        print_error(f"Socket test failed: {e}")
        return False


def execute_attack(config):
    """Execute the DNS attack with given configuration."""
    print_header("Initializing DNS Random Subdomain Query Flood attack...")
    print_info("🎯 Target DNS server will receive random subdomain queries")
    print_info("🎭 Each query will appear to come from a different IP address")
    print_info("💻 Monitor your DNS server logs to see the attack in action")
    print_warning("Press Ctrl+C to stop the attack early")
    print()

    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[
            logging.FileHandler("dns_random_subdomain_flood_test.log"),
            logging.StreamHandler(),
        ],
    )

    try:
        attack = DNSRandomSubdomainQueryFlood(
            target_ip=config["target_ip"],
            target_port=config["target_port"],
            duration=config["duration"],
            threads=config["threads"],
            base_domains=config["base_domains"],
            query_types=config["query_types"],
        )

        print_info("Starting DNS Random Subdomain Query Flood attack...")
        attack.attack()

    except KeyboardInterrupt:
        print_warning("\nDNS flood attack stopped by user.")
    except Exception as e:
        print_error(f"Error during DNS attack: {e}")
        logging.error(f"DNS Random Subdomain Query Flood attack failed: {e}")


def main():
    print_header("=" * 70)
    print_header("DNS RANDOM SUBDOMAIN QUERY FLOOD ATTACK SIMULATOR")
    print_header("=" * 70)

    print_warning("⚠️  WARNING: This tool is for educational purposes only!")
    print_warning(
        "⚠️  Only use against systems you own or have explicit permission to test!"
    )
    print_warning(
        "⚠️  This attack can overwhelm DNS servers and affect network services!"
    )
    print()

    display_attack_info()

    # Get default configuration
    config = get_default_config()
    display_default_config(config)

    # Ask user if they want to customize
    customize = (
        input("Do you want to customize the attack parameters? (y/n): ").lower().strip()
    )

    if customize == "y":
        print_header("Customizing Attack Parameters:")
        customize_basic_params(config)
        customize_advanced_params(config)

    print()
    display_final_config(config)

    # Confirm before starting
    confirm = (
        input("Are you sure you want to start the DNS flood attack? (yes/no): ")
        .lower()
        .strip()
    )
    if confirm != "yes":
        print_warning("Attack cancelled.")
        return

    # Check for administrator privileges
    if not check_admin_privileges():
        return

    print()
    execute_attack(config)

    print()
    print_header("Attack Test Completed")
    print_info("Check the log file: dns_random_subdomain_flood_test.log")
    print_info("Monitor your target DNS server for the impact assessment")


if __name__ == "__main__":
    main()
