import rsa 
from multiprocessing import shared_memory
import time
import sysimport rsa
from multiprocessing import shared_memory

# 1. Attach to the existing shared memory
try:
    shm = shared_memory.SharedMemory(name='my_rsa_key_block')
except FileNotFoundError:
    print("Error: The Key Provider script is not running!")
    exit()

# 2. Read the bytes
# We read the whole buffer (we know it's a valid key object)
key_bytes = bytes(shm.buf[:4096]).strip(b'\x00') # strip() removes empty null bytes

# 3. Load the key
private_key = rsa.PrivateKey.load_pkcs1(key_bytes)
print("Private key successfully retrieved from RAM.")

# 4. Sign a message
message = "This message was signed using a key from shared memory!".encode('utf-8')
signature = rsa.sign(message, private_key, 'SHA-256')

print("Message signed successfully!")
print(f"Signature: {signature.hex()[:50]}...")

# 5. Clean up
shm.close()