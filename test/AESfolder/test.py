from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
import time
import sys
import base64

PASSWORD = "mysecretpassword"
SECRET_KEY = hashlib.sha256(PASSWORD.encode()).digest()[:16]  # Derive a 256-bit key from the password
# print ("your key is: ", SECRET_KEY.hex())

Fixed_iv = bytes(16)  # A fixed IV for demonstration (not secure for real use)


def encrypt(message, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    padded_data = pad(message.encode('utf-8'), AES.block_size)
    print("Padded data:", padded_data.hex())
    ciphertext = cipher.encrypt(padded_data)
    print("key: ", key.hex())
    return ciphertext

def decrypt(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    decrypted_padded = cipher.decrypt(ciphertext)
    decrypted = unpad(decrypted_padded, AES.block_size)
    return decrypted.decode('utf-8')

message = "this is a secret message, and a test"
chipertext = encrypt(message, SECRET_KEY, Fixed_iv)
print("Encrypted message (hex):", chipertext.hex())
print("key in bytes:", len(SECRET_KEY))
decrypted_message = decrypt(chipertext, SECRET_KEY, iv=Fixed_iv)
print("Decrypted message:", decrypted_message)