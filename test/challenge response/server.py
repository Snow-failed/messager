import Cryptodome as Crypto
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import unpad
import hashlib, socket
from scapy.all import Raw, sniff

Password = "this is a password"

def generate_challenge():
    data = get_random_bytes(32)
    ch = hashlib.sha256(data).digest()[:16]    
    return ch


def send(data):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
      bytes_data =data.encode('utf-8')
    except:
      bytes_data =  data 

    sock.sendto(bytes_data, ("10.57.38.208", 53530))
        

def receive():
    result = {"data": None}

    # Bind a dummy socket so the OS doesn't send ICMP Port Unreachable
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 53530))

    def get_packet(packet):
        if packet.haslayer(Raw):
            try:
                result["data"] = packet[Raw].load.decode('utf-8')
                return True
            except Exception:
                pass
        return False

    try:
        sniff(
            filter="udp port 53530",
            stop_filter=get_packet,  # prn= removed, no need to call twice
            store=False,
            count=1
        )
        return result["data"]
    finally:
        sock.close()  # Always release the socket

def verify (challenge, response, password):
    try:
        password = hashlib.sha256(password.encode("utf-8")).digest()
        iv = response[:16]
        text = response[:16]
        cipher = AES.new(Password, AES.MODE_CBC, iv)

        decrypted_padded = cipher.decrypt(text)
        decrypted_data = unpad(decrypted_padded, AES.block_size)

        if decrypted_data == challenge:
            return True
        else:
            return False
    
    except ValueError:
        return False

if __name__ == "__main__":

    print("wacht op start van client") 
    start = receive()
    print(f"dit is ontvangen:{start}")    
    
    challenge = generate_challenge()
    send(challenge)
    response = receive()

    result = verify(challenge, response)
    if result == True:
        send("je hebt toegang")
    else:
        send("je hebt geen toegagn")
