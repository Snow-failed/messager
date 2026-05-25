try: 
    import Cryptodome as Crypto
    from Cryptodome.Cipher import AES
    from Cryptodome.Util.Padding import pad, unpad
    from Cryptodome.Random import get_random_bytes
except ModuleNotFoundError:
    import Crypto
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
    from Crypto.Random import get_random_bytes

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

import hashlib
import json
import os



def encrypt(message_file, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    chunk_size = 64 * 1024  # 64KB
    hex_chunk = []

    with open(message_file, 'rb') as f_in:      
        while True:
            chunk = f_in.read(chunk_size)
            
            if len(chunk) < chunk_size:
                hex_chunk.append(cipher.encrypt(pad(chunk, AES.block_size)).hex())
                break
            hex_chunk.append(cipher.encrypt(chunk).hex())
    return hex_chunk


def load_public_key(file_path):
    with open(file_path, "rb") as key_file:
        return serialization.load_pem_public_key(key_file.read())


def encrypt_key(aes_key, public_key) -> str:
    encrypted_bytes = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_bytes.hex()

# open
# WE HAVE A MAIN

def encryption_daan(public_key):  
    Random_key = get_random_bytes(16) # AES-128 key is 16 bytes long  
    iv = get_random_bytes(16)

    script_dir = os.path.dirname(os.path.abspath(__file__))
    message_file = os.path.join(script_dir, "message.txt")
    output_file = os.path.join(script_dir, "output.json")

    print("Encrypting file...")
    # This calls your AES encryption function
    encrypt_message = encrypt(message_file, Random_key, iv)
    print("File encrypted successfully!")
    
    # Direct RSA encryption using the public_key object passed in
    encrypted_key_bytes = public_key.encrypt(
        Random_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    encrypted_key = encrypted_key_bytes.hex()

    payload = {
        "iv": iv.hex(),
        "encrypted_key": encrypted_key,
        "encrypted_message": encrypt_message
    }
    
    with open(output_file, 'w') as f_out:
        json.dump(payload, f_out, indent=2)
        
    print("Encrypted key (hex):", encrypted_key)
    return payload