from Crypto.Cipher import AES
import os
from pwn import *
import json
from zlib import crc32



"""
OFB is simply ECB with custom IV, but the flawness of this challenge is IV fixed

POC:
key = os.urandom(32)
cipher = AES.new(key, AES.MODE_OFB, iv = b'\x00'*16)

m = b'abcdefgh'*4


print(cipher.encrypt(m))

tmp = AES.new(key, AES.MODE_ECB).encrypt(b'\x00'*16)

print(tmp, len(tmp))
print(xor(tmp, m)) # the first block is the same, due to im lazy to modify iv for the second one
"""



io = remote("chall.fcsc.fr", "2150")

io.sendlineafter(b'>>> ', b'1')
io.sendlineafter(b'Are you new ? (y/n) ', b'y')
io.sendlineafter(b'Name: ', 'hehe')
io.recvuntil(b'Here is your token:\n')
c = bytes.fromhex(io.recvline().rstrip().decode())
print(len(c))

name = 'hehe'
m = json.dumps({
					"name": name,
					"admin": False,
				}).encode()

print(m, len(m))

tag = crc32(m)

print(tag)


ims = [xor(i, j) for i, j in [(m[:16], c[:16]), (m[16:32], c[16:32])]]
ims.append(xor(c[-4:], int.to_bytes(tag, 4, 'big')))

modified_m = json.dumps({
					"name": 'toto',
					"admin ": True,
				}).encode()

print(modified_m, len(modified_m))
mod_tag = int.to_bytes(crc32(modified_m), 4, 'big')

print(mod_tag)


mod_ct = [xor(i, j) for i, j in [(ims[0], modified_m[:16]), (ims[1], modified_m[16:32])]]
mod_ct = b''.join(mod_ct) + xor(mod_tag, ims[-1])

print(mod_ct)


io.sendlineafter(b'>>> ', b'1')
io.sendlineafter(b'Are you new ? (y/n) ', b'n')
io.sendlineafter(b'Token: ', mod_ct.hex())


io.interactive()



