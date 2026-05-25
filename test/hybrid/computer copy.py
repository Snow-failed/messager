import base64
import json
import os
import threading
import time
from scapy.all import send, sniff, Raw, IP, UDP, DNS, DNSQR
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import random
import socket
# --- STEP 1: INITIALIZE AND STORE SERVER KEYS ---
script_dir = os.path.dirname(os.path.abspath(__file__))
private_key_path = os.path.join(script_dir, "private_key.pem")
public_key_path = os.path.join(script_dir, "public_key.pem")
def key_checker(private_key_path, public_key_path):
    if os.path.exists(private_key_path) and os.path.exists(public_key_path):
        print("Loading existing RSA keys from disk...")
        with open(private_key_path, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
        with open(public_key_path, "rb") as f:
            public_key = serialization.load_pem_public_key(f.read())
    else:
        print("No keys found. Generating new RSA 2048 keypair...")
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()

        # Save them to disk so the client can find them next time
        with open(private_key_path, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        with open(public_key_path, "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
    return private_key, public_key 

# Prepare the PEM string to broadcast to the network



# --- STEP 2: BROADCAST PUBLIC KEY IN THE BACKGROUND ---

def key_broadcaster():
    payload = json.dumps({"public_key": public_pem}).encode('utf-8')
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    while True:
        sock.sendto(payload, ("10.57.33.198", 53530))
        time.sleep(0.5)

# Start the broadcast loop on a background thread


# --- STEP 3: SNIFFER AND CHUNK DECRYPTER ---
def parse_and_decrypt(packet):
    if packet.haslayer(Raw):
        try:
            payload_str = packet[Raw].load.decode('utf-8')
            data = json.loads(payload_str)
            
            # Verify the packet contains our encrypted message fields
            if "encrypted_key" in data and "encrypted_message" in data:
                print(f"\n[Intercepted Covert Transmission from {packet[IP].src}]")
                
                # 1. Parse out hex values from JSON
                iv = bytes.fromhex(data["iv"])
                encrypted_key_bytes = bytes.fromhex(data["encrypted_key"])
                hex_chunks = data["encrypted_message"]

                # 2. Decrypt the AES key using the RSA Private Key
                aes_key = private_key.decrypt(
                    encrypted_key_bytes,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                print("RSA Decryption successful. Recovered AES Session Key.")

                # 3. Setup the AES CBC cipher for decryption arp
                cipher = AES.new(aes_key, AES.MODE_CBC, iv=iv)
                decrypted_text = ""

                # 4. Process each chunk sequentially
                for i, chunk_hex in enumerate(hex_chunks):
                    chunk_bytes = bytes.fromhex(chunk_hex)
                    decrypted_bytes = cipher.decrypt(chunk_bytes)
                    
                    # If it's the final chunk, strip away the PKCS7 padding
                    if i == len(hex_chunks) - 1:
                        decrypted_text += unpad(decrypted_bytes, AES.block_size).decode('utf-8')
                    else:
                        decrypted_text += decrypted_bytes.decode('utf-8')

                print("\n--- DECRYPTED MESSAGE CONTENT ---")
                print(decrypted_text)
                print("---------------------------------")
                
        except Exception as e:
            # Silently pass background mDNS traffic noise
            pass

if __name__ == "__main__":
    script_dir = os.path.dirname(os.path.abspath(__file__))
    private_key_path = os.path.join(script_dir, "private_key.pem")
    public_key_path = os.path.join(script_dir, "public_key.pem")
    private_key, public_key = key_checker(private_key_path, public_key_path)


    public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    threading.Thread(target=key_broadcaster, daemon=True).start()
    
    print("Server active. Listening for incoming chunked messages...")
    sniff(filter="udp port 53530", prn=parse_and_decrypt, store=False)