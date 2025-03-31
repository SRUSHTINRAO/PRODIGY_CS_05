from scapy.all import sniff

# Function to process captured packets
def packet_callback(packet):
    print("="*50)
    print(f"Packet Captured:")
    
    if packet.haslayer("IP"):  # Check if it's an IP packet
        src_ip = packet["IP"].src
        dst_ip = packet["IP"].dst
        protocol = packet["IP"].proto
        
        print(f"Source IP: {src_ip}")
        print(f"Destination IP: {dst_ip}")
        print(f"Protocol: {protocol}")

    if packet.haslayer("TCP"):  # Check if it's a TCP packet
        print("TCP Packet Detected")
        print(f"Source Port: {packet['TCP'].sport}")
        print(f"Destination Port: {packet['TCP'].dport}")

    if packet.haslayer("UDP"):  # Check if it's a UDP packet
        print("UDP Packet Detected")
        print(f"Source Port: {packet['UDP'].sport}")
        print(f"Destination Port: {packet['UDP'].dport}")

    if packet.haslayer("Raw"):  # If there is raw payload data
        print("Payload:", packet["Raw"].load)

# Start sniffing packets
print("Starting packet sniffer... (Press Ctrl+C to stop)")
sniff(prn=packet_callback, store=False)  # `store=False` prevents memory overload
