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
# We use a dictionary to hold our result so the callback can modify it
    result = {"data": None}

    def get_packet(packet):
        if packet.haslayer(Raw):
            try:
                # Decode the data and store it in our result dictionary
                result["data"] = packet[Raw].load.decode('utf-8')
                # Returning True here tells stop_filter to halt the sniffing
                return True 
            except Exception:
                # Silently pass background noise or decoding errors
                pass
        return False

    try:
        # sniff() runs until stop_filter returns True
        sniff(
            filter="udp port 53530", 
            prn=get_packet, 
            stop_filter=get_packet,  # This stops the sniff loop when a packet matches
            store=False, 
            count=1  # Optional: stops after 1 packet matches anyway
        )
        return result["data"]
    except Exception:
        return None

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
