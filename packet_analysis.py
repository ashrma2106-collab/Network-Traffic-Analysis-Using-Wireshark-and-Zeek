from scapy.all import rdpcap

def analyze_packets(file):
    packets = rdpcap(file)

    print("=" * 40)
    print(" Network Traffic Analysis Report")
    print("=" * 40)
    print(f"Total Packets Captured: {len(packets)}")

    protocol_count = {}

    for packet in packets:
        proto = packet.summary().split()[0]
        protocol_count[proto] = protocol_count.get(proto, 0) + 1

    print("\nProtocol Summary:")
    for protocol, count in protocol_count.items():
        print(f"{protocol}: {count}")

if __name__ == "__main__":
    filename = input("Enter the path to a .pcap file: ")
    analyze_packets(filename)
