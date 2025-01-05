#!/usr/bin/env python3

from scapy.all import sniff, IP, TCP
from collections import defaultdict
import os
import logging

# Configuration
THRESHOLD_PORTS = 5  # Number of unique ports to trigger port scan detection
BLOCK_DURATION = 3600  # Duration to block IP (in seconds)
LOG_FILE = "intrusion.log"
EMAIL = "admin@example.com"  # Replace with your email

# Set up logging
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format='%(asctime)s - %(message)s')

# Track connections per IP
ip_connections = defaultdict(set)

def block_ip(ip):
    """
    Block an IP address using iptables.
    """
    try:
        os.system(f"iptables -A INPUT -s {ip} -j DROP")
        logging.info(f"Blocked IP: {ip}")
        print(f"[+] Blocked IP: {ip}")
    except Exception as e:
        logging.error(f"Failed to block IP {ip}: {e}")
        print(f"[-] Error blocking IP {ip}: {e}")

def detect_port_scan(packet):
    """
    Detect port scanning by tracking unique ports per IP.
    """
    if IP in packet and TCP in packet:
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport

        # Track unique ports for the source IP
        ip_connections[src_ip].add(dst_port)

        # Check if the number of unique ports exceeds the threshold
        if len(ip_connections[src_ip]) > THRESHOLD_PORTS:
            print(f"[!] Port scan detected from {src_ip}")
            logging.warning(f"Port scan detected from {src_ip} on ports: {ip_connections[src_ip]}")
            block_ip(src_ip)  # Block the IP
            ip_connections[src_ip].clear()  # Reset the tracked ports

def start_sniffing():
    """
    Start sniffing network traffic.
    """
    print("[*] Starting network traffic analysis...")
    try:
        sniff(prn=detect_port_scan, filter="tcp", store=False)
    except KeyboardInterrupt:
        print("\n[*] Stopping network traffic analysis.")
    except Exception as e:
        logging.error(f"Error during sniffing: {e}")
        print(f"[-] Error during sniffing: {e}")

if __name__ == "__main__":
    # Check if running as root (required for iptables)
    if os.geteuid() != 0:
        print("[-] This script must be run as root.")
        exit(1)

    # Start the intrusion detection system
    start_sniffing()
