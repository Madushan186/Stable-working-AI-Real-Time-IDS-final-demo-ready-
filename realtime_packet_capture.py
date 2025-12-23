from scapy.all import sniff

def packet_handler(packet):
    print(packet.summary())

print("Starting live packet capture on en0... Press Ctrl+C to stop.")

sniff(
    iface="en0",     # Wi-Fi interface
    prn=packet_handler,
    store=False
)
