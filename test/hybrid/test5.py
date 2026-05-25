try: 
    import Cryptodome as Crypto
    from Cryptodome.Cipher import AES
    from Cryptodome.Util.Padding import unpad
except ModuleNotFoundError:
    import Crypto
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad

import json
import os
import threading
import time
from scapy.all import send, sniff, Raw, IP, UDP, DNS, DNSQR
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from cryptography.hazmat.primitives import serialization, hashes
import sys

# Import your custom encryption engine
import encryption_daan

def search_public_keys(timeout=15):
    """Listens to the network to catch the receiver's public key."""
    print("Listening for Receiver's Public Key on UDP 5353...")
    captured_keys = []

    def process_packet(packet):
        if packet.haslayer(Raw):
            try:
                payload_str = packet[Raw].load.decode('utf-8')
                data = json.loads(payload_str)
                if "public_key" in data:
                    print("\nTarget public key captured!")
                    key_bytes = data["public_key"].encode('utf-8')
                    pub_key = serialization.load_pem_public_key(key_bytes)
                    captured_keys.append(pub_key)
            except Exception:
                pass

    # Stop sniffing immediately when we catch 1 key
    sniff(filter="udp port 5353", prn=process_packet, stop_filter=lambda x: len(captured_keys) > 0, timeout=timeout)
    
    if not captured_keys:
        print("Error: Timed out waiting for a public key. Is the receiver running?")
        sys.exit(1)
        
    return captured_keys[0]

def send_secret_mdns(json_payload_string: str):
    """Broadcasts the encrypted payload over mDNS."""
    print("Broadcasting encrypted payload over mDNS (224.0.0.251:5353)...")
    print("Press Ctrl+C to stop.")

    packet = (
        IP(dst="224.0.0.251") / 
        UDP(sport=5353, dport=5353) / 
        DNS(rd=0, qd=DNSQR(qname="covert.local", qtype="TXT")) / 
        Raw(load=json_payload_string.encode('utf-8'))
    )

    try:
        while True:
            send(packet, verbose=False)
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nTransmission stopped.")
        sys.exit(0)

if __name__ == "__main__":
    # 1. Grab the key from the air
    public_key = search_public_keys(timeout=15)
    
    # 2. Hand it to your engine to encrypt message.txt
    print("Passing key to encryption_daan...")
    payload_dict = encryption_daan.encryption_daan(public_key)
    
    # 3. Convert the returned dictionary to a JSON string and send it
    send_secret_mdns(json.dumps(payload_dict))