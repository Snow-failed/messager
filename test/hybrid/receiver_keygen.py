from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import os


if __name__ == "__main__":
    # The secret message to embed
    script_dir       = os.path.dirname(os.path.abspath(__file__))
    private_key_path = os.path.join(script_dir, "private_key.pem")
    public_key_path  = os.path.join(script_dir, "public_key.pem")
    private_exists   = os.path.exists(private_key_path)
    public_exists    = os.path.exists(public_key_path)

    if private_exists and public_exists:
        print("Keys already exist, skipping generation.")
    else:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key  = private_key.public_key()

        if private_exists:
            os.remove(private_key_path)
            print("Deleted orphaned private key, regenerating pair...")
        elif public_exists:
            os.remove(public_key_path)
            print("Deleted orphaned public key, regenerating pair...")
        else:
            print("No keys found, generating new pair...")

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        with open(private_key_path, "wb") as f:
            f.write(private_pem)
        with open(public_key_path, "wb") as f:
            f.write(public_pem)
        print("Keys saved.")
        