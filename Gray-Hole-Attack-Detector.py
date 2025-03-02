# -*- coding: utf-8 -*-
"""
Created on Sun Mar 2 6:10:47 2025

@author: IAN CARTER KULANI

"""

from colorama import Fore
import pyfiglet
import os
font=pyfiglet.figlet_format("Gray Hole Attack Detector")
print(Fore.GREEN+font)

import scapy.all as scapy
import time

# This dictionary will store packets with their sequence numbers
packet_sequence = {}

def packet_callback(packet):
    if packet.haslayer(scapy.IP):
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        seq_num = packet.seq

        if dst_ip not in packet_sequence:
            packet_sequence[dst_ip] = []

        # Store packet with sequence number
        packet_sequence[dst_ip].append(seq_num)

        print(f"Received packet from {src_ip} to {dst_ip} with sequence number: {seq_num}")

def detect_gray_hole(ip_address):
    print(f"Monitoring traffic to/from {ip_address} for potential Gray Hole Attack...")
    
    start_time = time.time()
    while time.time() - start_time < 60:  # Monitor for 1 minute for example
        # Look for missing packets or irregularities in sequence
        if ip_address in packet_sequence:
            seq_nums = packet_sequence[ip_address]
            if len(seq_nums) > 1:
                # Check for missing packets in the sequence
                seq_nums.sort()
                for i in range(1, len(seq_nums)):
                    if seq_nums[i] != seq_nums[i-1] + 1:
                        print(f"Missing packets detected between {seq_nums[i-1]} and {seq_nums[i]}")
                        print(f"Potential Gray Hole Attack detected!")
                        return
        time.sleep(1)

    print(f"No Gray Hole detected within the last minute of monitoring.")

def start_monitoring():
    # Get the user's IP address input
    ip_address = input("Enter the IP address to monitor for Gray Hole Attack:")

    # Start sniffing for packets
    print("Starting packet capture...")
    scapy.sniff(prn=packet_callback, filter=f"ip host {ip_address}", store=0, timeout=60)

    # After capturing, analyze the traffic for Gray Hole attack
    detect_gray_hole(ip_address)

if __name__ == "__main__":
    start_monitoring()
