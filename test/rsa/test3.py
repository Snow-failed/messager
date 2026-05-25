import rsa 
from multiprocessing import shared_memory
import time
import sys

# 1. Generate key
print("Generating 2048-bit RSA key...")
public_key, private_key = rsa.newkeys(2048)
key_bytes = private_key.save_pkcs1()

# 2. Create Shared Memory (Size: 4096 bytes is plenty for a 2048-bit key)
# The name 'my_rsa_key_block' is the identifier for the other script
shm = shared_memory.SharedMemory(name='test4', create=True, size=4096)

# 3. Write data to the shared memory
# We store the length first, then the data, so the reader knows how much to read
shm.buf[:len(key_bytes)] = key_bytes

print(f"Key loaded into RAM. {len(key_bytes)} bytes stored.")
print("The Key Provider is now running. Do not close this window.")

try:
    while True:
        time.sleep(1) # Keep script alive
except KeyboardInterrupt:
    # Clean up when you stop the script
    shm.close()
    shm.unlink()
    print("\nShared memory closed and unlinked.")