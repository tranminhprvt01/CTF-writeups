
from pwn import *


def flip_bit(s:bytes, bit_len):
    mask = (1<<bit_len)-1
    return xor(s, mask.to_bytes(bit_len//8, 'big'))




while True:
    io = remote("desfunctional.2024.ctfcompetition.com", 1337)#process(["python", "chall.py"])


    io.sendlineafter(b'3. Get the flag\n', b'1')
    # io.recvline() #debug
    ct = bytes.fromhex(io.recvline().rstrip().decode())

    prefix = ct[:8]


    flip_ct = flip_bit(ct, len(ct)*8)


    print("calc", flip_ct.hex())


    for i in range(10):
        io.sendlineafter(b'3. Get the flag\n', b'2')
        io.sendlineafter(b'(hex) ct: ', flip_ct.hex())

        # io.recvline()
        # io.recvline()
        # io.recvline()
        # io.recvline()

        flip_m = bytes.fromhex(io.recvline().rstrip().decode())



    flip_m = flip_bit(flip_m, len(flip_m)*8)[:8] + flip_m[8:]



    io.sendlineafter(b'3. Get the flag\n', b'3')
    io.sendlineafter(b'(hex) pt: ', flip_m.hex())

    if io.recvline().rstrip() == b'Not quite right':
        continue
    else:
        io.interactive()
        break


#CTF{y0u_m4y_NOT_g3t_th3_k3y_but_y0u_m4y_NOT_g3t_th3_c1ph3rt3xt_as_w3ll}




"""
from pwn import *
import signal
import os
import random
import sys
from Crypto.Cipher import DES3



def flip_bit(s:bytes, bit_len):
    #print(len(s))
    mask = (1<<bit_len)-1
    #print(mask, mask.bit_length())
    #print(mask.to_bytes(bit_len//8, 'little'))
    return xor(s, mask.to_bytes(bit_len//8, 'little'))

m1 = os.urandom(64)
m2 = flip_bit(m1, 64*8)


iv = os.urandom(8)
k1 = os.urandom(24)
k2 = flip_bit(k1, 24*8)

c1 = DES3.new(k1, DES3.MODE_CBC, iv=iv).encrypt(m1)
m1_ = DES3.new(k2, DES3.MODE_CBC, iv=iv).decrypt(flip_bit(c1, 64*8))

print(m1_.hex())
print(flip_bit(m1_, 64*8).hex())
print(m1.hex())
"""







