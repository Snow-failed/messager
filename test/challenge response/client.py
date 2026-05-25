import hashlib, socket, time, json
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from scapy.all import Raw, sniff

password = "this is a password"

def create_hash(password):
    password_1 = hashlib.sha256(password.encode('utf-8')).digest()[:16]
    print(f"SHA-256 hash (first 16 bytes) of the password: {password_1}")
    return password_1

def send(data):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
      bytes_data =data.encode('utf-8')
    except:
      bytes_data =  data
    try:
        sock.sendto(bytes_data, ("10.57.33.198", 53530))
    finally:
        sock.close()

def receive():
    result = {"data": None}

    # Bind a dummy socket so the OS doesn't send ICMP Port Unreachable
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # test line 
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    sock.bind(("0.0.0.0", 53530))

    def get_packet(packet):
        if packet.haslayer(Raw):
            try:
                result["data"] = packet[Raw].load
                return True
            except Exception:
                print("get_packet error")
                pass
        return False

    try:
        sniff(
            filter="udp port 53530",
            stop_filter=get_packet,  # prn= removed, no need to call twice
            store=False,
            count=1
        )
        print(result)
        return result["data"]
    finally:
        sock.close() 
        
def create_reponse(challenge, hash_password):
    print(len(challenge))
    msg_bytes = len(challenge)
    encrypted = bytes([challenge[i] ^ hash_password[i % len(hash_password)] for i in range(msg_bytes)])
    return encrypted

def create_response(key, challenge):
    Fixed_iv = bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv=Fixed_iv)
    padded_data = pad(challenge.encode('utf-8'), AES.block_size)
    print("Padded data:", padded_data.hex())
    ciphertext = cipher.encrypt(padded_data)
    print("key ", key.hex())
    return ciphertext



if __name__ == "__main__":
    send("hello, its me")
    challenge = receive()
    print(challenge.hex())

    hash_password = create_hash(password)
    
    response = create_reponse(hash_password, challenge)
    print(response.hex())
    send("dit is de tweede keer")
    send(response)
    result = receive()
    print(f"the result is {result}")
    