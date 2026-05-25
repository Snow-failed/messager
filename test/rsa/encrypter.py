import sys
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

Tekst = "This is a secret message that needs to be encrypted using RSA encryption."
PUBLIC_KEY_FILE = "public_key.pem"

def load_public_key(file_path):
    with open(file_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read()
        )
    return public_key

def encrypt_rsa(message, public_key) -> str:
    ciphertext = public_key.encrypt(
        message.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return ciphertext.hex()

if __name__ == "__main__":
    try:
        public_key = load_public_key(PUBLIC_KEY_FILE)
    except Exception as e:
        print(f"Error loading public key: {e}")
        sys.exit(1)

    encrypted_message = encrypt_rsa(Tekst, public_key)
    print("Encrypted message (hex):", encrypted_message)
