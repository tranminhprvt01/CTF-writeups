from pwn import *
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

io = remote("54.85.45.101", 8001)


# client_priv = os.urandom(32)
# client_pub = x25519.scalar_base_mult(client_priv)


client_pub = b'\x00'*32
print(client_pub)


io.sendline(json.dumps({"client_pub": client_pub.hex()}))
io.interactive()
print(io.recvline().rstrip().decode())
data = 1
print(data)
iv = data['iv']
ct = data['ct']

secret = client_pub #lmao


cipher = Cipher(algorithms.AES(secret), modes.CTR(iv))

print(cipher.decryptor().update(ct))




