
from scapy.all import Ether, IP, UDP, BOOTP, DHCP, sendp
import random
import time

# Same MAC used repeatedly (benign client behavior)
CLIENT_MAC = "08:00:27:aa:bb:cc"
mac_bytes = bytes.fromhex(CLIENT_MAC.replace(":", ""))

def send_benign_dhcp_discover(count=100, iface="eth0"):
    for i in range(count):
        # Vary the inter-packet time to simulate a human client
        delay = random.uniform(0.05, 0.2)  # More jitter = higher IAT entropy

        pkt = Ether(src=CLIENT_MAC, dst="ff:ff:ff:ff:ff:ff") / \
              IP(src="0.0.0.0", dst="255.255.255.255") / \
              UDP(sport=68, dport=67) / \
              BOOTP(chaddr=mac_bytes[:16]) / \
              DHCP(options=[("message-type", "discover"), "end"])

        sendp(pkt, iface=iface, verbose=False)
        time.sleep(delay)

    print(f"[?] Sent {count} benign DHCP Discover packets.")

# Run it
if __name__ == "__main__":
    send_benign_dhcp_discover()
