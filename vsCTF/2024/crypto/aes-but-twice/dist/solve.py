
from pwn import *

io = remote("vsc.tf", 5000)

C_ctr = bytes.fromhex(io.recvline().rstrip().decode())
C_cbc = bytes.fromhex(io.recvline().rstrip().decode())
nonce = bytes.fromhex(io.recvline().rstrip().decode())
print(len(C_ctr))

flag = []

C_ = C_cbc[-16:]
for i in range(3):
    counter_i = nonce + b'\x00'*7 + i.to_bytes(1, 'big')
    print(counter_i.hex())

    P_ = xor(counter_i, C_)

    print(P_)


    io.sendline(P_.hex())

    C = bytes.fromhex(io.recvline().rstrip().decode())
    enc_counter_i = bytes.fromhex(io.recvline().rstrip().decode())




    F_ = xor(enc_counter_i, C_ctr[16*i:16*(i+1)])[:16]
    flag.append(F_)


    print(F_)

    C_ = enc_counter_i[-16:]



print(b''.join(flag))

io.interactive()



"""
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util import Counter

nonce = os.urandom(8)
iv = os.urandom(16)
key = os.urandom(16)
CTR_ENC = AES.new(key, AES.MODE_CTR, nonce=nonce)
CBC_ENC = AES.new(key, AES.MODE_CBC, iv=iv)


def ctr_encrypt(data):
    return CTR_ENC.encrypt(pad(data, 16)).hex()


def cbc_encrypt(data):
    print(data, pad(data, 16))
    return CBC_ENC.encrypt(pad(data, 16)).hex()




p1 = (b'\x00'*16)
p2 = (b'\x00'*16)



c1 = cbc_encrypt(p1)
c2 = cbc_encrypt(p2)


print(c1)
print(c2)
"""

