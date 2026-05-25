import time
import sys
import hashlib
from scapy.all import IP, UDP, DNS, DNSQR, send

# Generate a random secret key
PASSWORD = "mysecretpassword"
SECRET_KEY = hashlib.sha256(PASSWORD.encode()).digest()  # Derive a 256-bit key from the password
print ("your key is: ", SECRET_KEY.hex())

def encrypt (message, key):
    # Simple XOR encryption for demonstration purposes
    msg_bytes = message.encode()
    encrypted = bytes([msg_bytes[i] ^ key[i % len(key)] for i in range(len(msg_bytes))])
    return encrypted.hex()


def send_secret_mdns(secret_message):
    """
    Sends a custom mDNS multicast request containing a hidden secret every second.
    """
    print("Starting mDNS covert channel to 224.0.0.251:5353...")
    print("Press Ctrl+C to stop.")

    # Standard mDNS Multicast destination IP and UDP port
    MDNS_MULTICAST_IP = "224.0.0.251"
    MDNS_PORT = 5353

    #encrypt the secret message using the generated key
    encrypted = encrypt(secret_message, SECRET_KEY)
    # Construct the network layers
    ip_layer = IP(dst=MDNS_MULTICAST_IP)
    udp_layer = UDP(sport=MDNS_PORT, dport=MDNS_PORT)

    # Construct the mDNS layer
    # mDNS queries generally use standard DNS structures but with local domains
    dns_layer = DNS(rd=0, qd=DNSQR(qname="covert.local", qtype="TXT"))

    # Append the secret message as raw payload data at the end of the packet
    packet = ip_layer / udp_layer / dns_layer / encrypted

    try:
        while True:
            send(packet, verbose=False)
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nScript terminated by user.")
        sys.exit(0)

if __name__ == "__main__":
    # The secret message to embed
    SECRET = "<GEHEIM=dit mag niemand weten>"

    send_secret_mdns(SECRET)