
""""""
from scapy.all import DNS, sniff, send, IP, UDP, DNSQR, Raw
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
import os, json, time, threading, encryption_daan, argparse

# ai open
parser = argparse.ArgumentParser(description="Send an encrypted message over mDNS")
parser.add_argument("--to",      required=True,  help="Receiver ID (e.g. laptop)")
parser.add_argument("--message", required=False, help="Path to message file (default: message.txt)")
args = parser.parse_args()

RECEIVER_ID  = args.to
CHUNK_SIZE   = 500
MDNS_IP      = "224.0.0.251"
MDNS_PORT    = 5353
message_file = args.message or os.path.join(script_dir, "message.txt")


if os.path.exists("private_key.pem") and os.path.exists("public_key.pem"):
    print("Keys already exist, skipping generation.")
    with open("public_key.pem", "rb") as f:
        public_key = f.read()
    with open("private_key.pem", "rb") as f:
        private_key = f.read()
    
else:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key  = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open("private_key.pem", "wb") as f:
        f.write(private_pem)
    with open("public_key.pem", "wb") as f:
        f.write(public_pem)
    print("Keys saved.")
# look at this before running
def send_public_key(public_key):
    # This function can be implemented to send the public key to the sender if needed
    print(f"sending public key to sender: {public_key}")
    response = (
        IP(dst=MDNS_IP) /
        UDP(sport=MDNS_PORT, dport=MDNS_PORT) /
        DNS(rd=0, qd=DNSQR(qname=f"{RECEIVER_ID}.local", qtype="TXT"), an=DNSRR(rrname=f"{RECEIVER_ID}.local", rdata=public_key.decode()))
    )
    
def handle_packet(pkt):
    if not (pkt.haslayer(DNS) and pkt.haslayer(Raw) and pkt.haslayer(IP)):
        return
    try:
        qname = pkt[DNSQR].qname.decode(errors='ignore').rstrip('.')
        sender_ip = pkt[IP].src
    except Exception:
        return
    
    if qname == f"{RECEIVER_ID}.reqkey.convert.local":
        with lock:
            if sender_ip in responded_to:
                return
            if sender_ip == active_sender[0]:
                return
            if sender_ip not in request_queue:
                print(f"Received key request from {sender_ip}")
                request_queue.append(sender_ip)
                responded_to.add(sender_ip)
        
        process_queue()
        return
    
parts = qname.split('.')
    if len(parts) < 5:
        print("Received malformed packet, ignoring.")
        return
    try:
        chunk_num, total = parts[2].split('of')
        chunk_num = int(chunk_num)
        total = int(total)
    except ValueError
        return

    if sender_ip not in received_chunks:
        received_chunks[sender_ip] = {}
    
    data = 
