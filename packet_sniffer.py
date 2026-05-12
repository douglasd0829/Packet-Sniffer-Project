from scapy.all import sniff, IP

# Counters
total_packets = 0
protocol_count = {
    "TCP": 0,
    "UDP": 0,
    "ICMP": 0,
    "OTHER": 0
}

# Process each packet
def process_packet(packet):
    global total_packets
    total_packets += 1

    if packet.haslayer(IP):
        src = packet[IP].src
        dst = packet[IP].dst
        proto_num = packet[IP].proto
        length = len(packet)

        # Identify protocol
        if proto_num == 6:
            proto = "TCP"
            protocol_count["TCP"] += 1
        elif proto_num == 17:
            proto = "UDP"
            protocol_count["UDP"] += 1
        elif proto_num == 1:
            proto = "ICMP"
            protocol_count["ICMP"] += 1
        else:
            proto = "OTHER"
            protocol_count["OTHER"] += 1

        # Print packet info
        print(f"Src: {src} -> Dst: {dst} | Protocol: {proto} | Length: {length}")

# Run sniffer
def run_sniffer():
    print("Sniffing for 30 seconds (TCP traffic only)...\n")

    sniff(
        prn=process_packet,
        store=False,
        timeout=30,
        filter="tcp"   # <-- FILTER: only TCP packets
    )

    # Summary
    print("\n========== SUMMARY ==========")
    print(f"Total Packets: {total_packets}")
    print(f"TCP: {protocol_count['TCP']}")
    print(f"UDP: {protocol_count['UDP']}")
    print(f"ICMP: {protocol_count['ICMP']}")
    print(f"Other: {protocol_count['OTHER']}")
    print("=============================")

# Run
if __name__ == "__main__":
    run_sniffer()