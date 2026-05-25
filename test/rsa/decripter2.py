import sys
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

PRIVATE_KEY_FILE = "private_key.pem"
Tekst = "This is a secret message that needs to be encrypted using RSA encryption."
PUBLIC_KEY_FILE = "public_key.pem"

def load_public_key(file_path):
    with open(file_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read()
        )
    return public_key

print("this is the public key:", PUBLIC_KEY_FILE)

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


def load_private_key(file_path):
    with open(file_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None
        )
    return private_key

def decrypt_rsa(ciphertext_hex: str, private_key) -> str:
    ciphertext = bytes.fromhex(ciphertext_hex)
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext.decode("utf-8")


if __name__ == "__main__":
    try:
        public_key = load_public_key(PUBLIC_KEY_FILE)
    except Exception as e:
        print(f"Error loading public key: {e}")
        sys.exit(1)

    encrypted_message = encrypt_rsa(Tekst, public_key)
    print("Encrypted message (hex):", encrypted_message)


    try:
        private_key = load_private_key(PRIVATE_KEY_FILE)
    except Exception as e:
        print(f"Error loading private key: {e}")
        sys.exit(1)

    try:
        decrypted_message = decrypt_rsa(encrypted_message, private_key)
        print("Decrypted message:", decrypted_message)
    except Exception as e:
        print(f"Decryption failed: {e}")
        print("Make sure you are using the private key that matches the public key used to encrypt.")
        sys.exit(1)