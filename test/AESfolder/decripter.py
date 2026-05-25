import hashlib
from scapy.all import DNS, sniff
from cryptography.fernet import Fernet


#hier moet de key
ENCRYPTED_HEX = ""
PASSWORD = "mysecretpassword"
SECRET_KEY = hashlib.sha256(PASSWORD.encode()).digest()  # Derive a 256-bit key from the password
print ("your key is: ", SECRET_KEY.hex())
cipher_suite = Fernet(SECRET_KEY)

def decrypt(encrypted_hex, key):
    encrypted_bytes = bytes.fromhex(encrypted_hex)
    decrypted_encrypted = cipher_suite.decrypt(encrypted_bytes)
    decrypted = bytes([decrypted_encrypted[i] ^ key[i % len(key)] for i in range(len(decrypted_encrypted))])
    return decrypted.decode()

def packet_handler(packet):
    if packet.haslayer(DNS):
        try:
            raw = bytes(packet[DNS].payload).decode("utf-8", errors="ignore").strip()
            message = decrypt(raw, SECRET_KEY)
            print(f"Received secret message: {message}")
        except Exception:
            pass

print("Listening for mDNS packets containing secret messages...")
sniff(filter="udp port 5353", prn=packet_handler)