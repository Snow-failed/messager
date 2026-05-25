#rsa decrypter and encrypter
import math
import secrets


message = "This is a secret message that needs to be encrypted using RSA encryption."
encrypt = message.encode('utf-8')

p = 11
q = 13
# n = RSA modulus
n = p * q
phi = (p-1)(q-1)

phi = (p - 1) * (q - 1)
result = math.gcd(7, phi)
print("gcd(7, phi) = ", result)

#test
if result != 1:
    print("wrong e, choose another one")
else:
    print("e is correct, we can continue")


# e = 7 and now d
e = 7 
# private key (n, d)
d = pow(e, -1, phi)
print("Private key (n, d): ", (n, d))
# public key (n, e)
print("Public key (n, e): ", (n, e)) 

# Encrypt the message using the public key

