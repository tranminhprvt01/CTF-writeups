from pwn import *


output = []

for atmp in range(0, 624, 8):
    io = remote("vsc.tf", 5001)
    io.sendlineafter(b">>> ", b','.join([str(i).encode() for i in range(atmp, atmp+8)]))
    for j in range(8):
        output.append(int(io.recvline().rstrip().decode()))
    ct = bytes.fromhex(io.recvline().rstrip().decode())
    io.close()


from randcrack import RandCrack

rc = RandCrack()

for i in output:
    rc.submit(i)

key = rc.predict_getrandbits(256)
nonce = rc.predict_getrandbits(256)


from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from hashlib import sha256
aes_key = sha256(str(key).encode()).digest()[:16]
aes_nonce = sha256(str(nonce).encode()).digest()[:16]
cipher = AES.new(aes_key, AES.MODE_GCM, nonce=aes_nonce)

print(cipher.decrypt(ct))




    