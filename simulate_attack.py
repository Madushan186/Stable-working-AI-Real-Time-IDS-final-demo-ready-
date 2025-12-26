import time
import socket
import sys
import random
from scapy.all import IP, TCP, Ether, sendp, get_if_hwaddr

# CONFIGURATION
INTERFACE = "en0"
TARGET_PORT = 8080
PACKET_COUNT = 100
DELAY = 0.01  # 100 packets/sec roughly

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except:
        return "127.0.0.1"

def simulate_http_flood():
    print(f"🚀 Starting HTTP Flood Simulation on {INTERFACE}...")
    
    try:
        src_ip = get_local_ip()
        dst_ip = "8.8.8.8" # Dummy destination that routes through en0
        src_mac = get_if_hwaddr(INTERFACE)
        dst_mac = "ff:ff:ff:ff:ff:ff" # Broadcast or Gateway MAC would be better, but broadcast ensures visibility
        
        print(f"📡 Sending from {src_ip} ({src_mac}) to {dst_ip}")
        print(f"⚡ Target Rate: {1/DELAY:.0f} req/s")
        
        # Pre-build packet (Ethernet + IP + TCP)
        # Using sendp (Layer 2) ensures it hits the interface regardless of routing table quirks for dummy IPs
        pkt = Ether(src=src_mac, dst=dst_mac) / \
              IP(src=src_ip, dst=dst_ip) / \
              TCP(dport=TARGET_PORT, sport=random.randint(1024, 65535), flags="S")

        count = 0
        start = time.time()
        
        for _ in range(PACKET_COUNT):
            sendp(pkt, iface=INTERFACE, verbose=0)
            count += 1
            if count % 20 == 0:
                sys.stdout.write(f"\r💥 Sent {count} packets...")
                sys.stdout.flush()
            time.sleep(DELAY)
            
        duration = time.time() - start
        print(f"\n✅ Finished. Sent {count} packets in {duration:.2f} seconds.")
        print(f"📊 Actual Rate: {count/duration:.2f} packets/sec")
        
    except PermissionError:
        print("\n❌ Permission denied: You must run this script with 'sudo'.")
    except OSError as e:
        print(f"\n❌ OS Error: {e}. Check if interface '{INTERFACE}' exists.")
    except Exception as e:
        print(f"\n❌ Unexpected Error: {e}")

if __name__ == "__main__":
    confirm = input(f"This will send {PACKET_COUNT} fake HTTP packets on {INTERFACE}. Type 'yes' to proceed: ")
    if confirm.lower() == "yes":
        simulate_http_flood()
    else:
        print("Cancelled.")

