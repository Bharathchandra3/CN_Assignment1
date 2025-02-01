#!/usr/bin/env python3
"""
sniffer.py
A raw packet sniffer for CS 331 assignment that captures packets replayed via tcpreplay
and computes the required metrics.
"""

from scapy.all import sniff, IP, TCP, Raw
import matplotlib.pyplot as plt
from collections import defaultdict
import time

# Global metrics variables
total_bytes = 0
packet_count = 0
packet_sizes = []
# Dictionaries to count flows (source and destination)
src_flow_counts = defaultdict(int)
dst_flow_counts = defaultdict(int)
# To record data transferred for each unique (srcIP:srcPort, dstIP:dstPort)
flow_data = defaultdict(int)

# For Part 2 questions, you may also wish to store packets that match conditions.
# For example:
matching_packets_q1 = []  # Question 1 in Part 2: absolute difference in ports == 54286, ACK flag set, last 4 digits of ack == '1203'
matching_packets_q2 = []  # Question 2: checksum starts with b5, urgent pointer=0, raw sequence last 4 digits '6183'
matching_packets_q3 = []  # Question 3: sum of ports between 10,000 and 20,000
matching_packets_q4 = []  # Question 4: ack number between 1678999000 and 1700000000

# You may also want to record the timestamps to measure pps and mbps.
capture_start = None

def process_packet(packet):
    global total_bytes, packet_count, capture_start
    if capture_start is None:
        capture_start = time.time()

    # We only process IP packets (and further, TCP in this example)
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        pkt_len = len(packet)
        total_bytes += pkt_len
        packet_count += 1
        packet_sizes.append(pkt_len)

        # Process TCP flows
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            # Extract addresses and ports
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            src_port = tcp_layer.sport
            dst_port = tcp_layer.dport

            # Update flow dictionaries
            src_flow_counts[src_ip] += 1
            dst_flow_counts[dst_ip] += 1

            # Create a unique flow key (tuple) and update data counter
            flow_key = (f"{src_ip}:{src_port}", f"{dst_ip}:{dst_port}")
            flow_data[flow_key] += pkt_len

            # ---------------------
            # Part 2: Answer Specific Questions
            # ---------------------

            # Q1 Conditions: abs(src_port - dst_port) == 54286, ACK flag set, last 4 digits of ack == '1203'
            if abs(src_port - dst_port) == 54286:
                if tcp_layer.flags & 0x10:  # ACK flag bit is set (0x10)
                    ack_str = str(tcp_layer.ack)
                    if ack_str.endswith("1203"):
                        matching_packets_q1.append((src_ip, dst_ip))

            # Q2 Conditions: TCP checksum starts with b5 (i.e. 0xb5____),
            # urgent pointer == 0, and the last 4 digits of the raw sequence number are '6183'
            # Note: Scapy computes checksum automatically; to get the raw checksum if available, you can use:
            if hasattr(tcp_layer, 'chksum'):
                checksum_hex = format(tcp_layer.chksum, '04x')
                if checksum_hex.startswith('b5'):
                    if tcp_layer.urgptr == 0:
                        seq_str = str(tcp_layer.seq)
                        if seq_str.endswith("6183"):
                            matching_packets_q2.append((src_ip, dst_ip, '0x' + checksum_hex))

            # Q3 Conditions: sum of source and destination ports between 10000 and 20000
            if 10000 <= (src_port + dst_port) <= 20000:
                matching_packets_q3.append(packet)

            # Q4 Conditions: acknowledgment number between 1678999000 and 1700000000 (raw ack)
            if tcp_layer.ack >= 1678999000 and tcp_layer.ack <= 1700000000:
                matching_packets_q4.append(packet)

def finalize():
    # Calculate statistics
    global total_bytes, packet_count, packet_sizes, capture_start
    if packet_count == 0:
        print("No packets captured.")
        return

    min_size = min(packet_sizes)
    max_size = max(packet_sizes)
    avg_size = total_bytes / packet_count

    print("----- Metrics -----")
    print(f"Total data transferred: {total_bytes} bytes")
    print(f"Total packets: {packet_count}")
    print(f"Minimum packet size: {min_size} bytes")
    print(f"Maximum packet size: {max_size} bytes")
    print(f"Average packet size: {avg_size:.2f} bytes")

    # Plot histogram of packet sizes
    plt.hist(packet_sizes, bins=20, edgecolor='black')
    plt.title("Packet Size Distribution")
    plt.xlabel("Packet Size (bytes)")
    plt.ylabel("Frequency")
    plt.savefig("packet_size_histogram.png")
    print("Histogram saved as 'packet_size_histogram.png'.")

    # Show unique source-destination pairs (for TCP flows)
    print("\n----- Unique Source-Destination Pairs (TCP flows) -----")
    for (src, dst), bytes_count in flow_data.items():
        print(f"{src} -> {dst} : {bytes_count} bytes")

    # Print flow dictionaries for source and destination counts
    print("\n----- Source IP Flow Count -----")
    for src_ip, count in src_flow_counts.items():
        print(f"{src_ip}: {count}")

    print("\n----- Destination IP Flow Count -----")
    for dst_ip, count in dst_flow_counts.items():
        print(f"{dst_ip}: {count}")

    # Identify which source-destination pair transferred the most data
    if flow_data:
        max_flow = max(flow_data.items(), key=lambda x: x[1])
        print("\n----- Flow with Maximum Data Transferred -----")
        print(f"{max_flow[0][0]} -> {max_flow[0][1]} : {max_flow[1]} bytes")

    # Compute and display capture speed
    duration = time.time() - capture_start
    pps = packet_count / duration
    mbps = (total_bytes * 8) / (duration * 1_000_000)  # bytes -> bits then to Mbps
    print(f"\nCapture duration: {duration:.2f} seconds")
    print(f"Top speed captured: {pps:.2f} packets per second (pps), {mbps:.2f} Mbps")

    # Print Part 2 matching packets
    print("\n----- Part 2: Specific Packet Matching Conditions -----")
    print("\nQ1: Packets with abs(src_port-dst_port)==54286, ACK flag set, ack ending with '1203'")
    for src, dst in matching_packets_q1:
        print(f"Source: {src}, Destination: {dst}")

    print("\nQ2: Packets with TCP checksum starting with b5, urgent pointer 0, seq ending with '6183'")
    for src, dst, chksum in matching_packets_q2:
        print(f"Source: {src}, Destination: {dst}, Checksum: {chksum}")

    print(f"\nQ3: Number of packets where (src_port + dst_port) is between 10,000 and 20,000: {len(matching_packets_q3)}")

    print(f"\nQ4: Number of packets with ack between 1678999000 and 1700000000: {len(matching_packets_q4)}")


if __name__ == "__main__":
    print("Starting packet capture... (Press Ctrl+C to stop)")
    try:
        # Sniff indefinitely on interface "eth0" (adjust interface as needed)
        # Use store=False if you want to process packets on the fly without keeping them in memory.
        sniff(iface="eth0", prn=process_packet, store=False)
        finalize()
    except KeyboardInterrupt:
        print("\nStopping capture...")
        finalize()
