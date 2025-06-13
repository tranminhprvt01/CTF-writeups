from Crypto.Util.number import long_to_bytes as ltb, bytes_to_long as btl
from Crypto.Util.Padding import pad
from pwn import *

#io = remote("45.122.249.68", 20024)#remote("localhost", 12345)
io = process(["python3", "chall.py"])

io.recvuntil(b"ct = '")
ct_gcm = bytes.fromhex(io.recvline().rstrip().decode()[:-1])
blocks_ct = [ct_gcm[i:i+16] for i in range(0, len(ct_gcm), 16)]


print(len(blocks_ct), len(blocks_ct)*16 == len(ct_gcm))


known = \
pad(b"""\
The security code is simple, an intricate dance of numbers.
A shield against intruders, a fortress for slumbers.
Digits align in harmony, a secret melody they sing,
Guarding the treasures of a realm, where secrets take their wing : \
""", 16)
blocks_pt = [known[i:i+16] for i in range(0, len(known), 16)]



iv = b'\x00'*16
io.sendlineafter(b"Your choice > ", b"2")
io.sendlineafter(b"Please give me your iv (in hex) > ", iv.hex())
io.sendlineafter(b"Please give me your ciphertext (in hex) > ", xor(blocks_ct[0], blocks_pt[0]).hex())
res = bytes.fromhex(io.recvline().rstrip().decode())
nonce = res[:12]
counter = btl(res[12:])

print(nonce, counter)


nonce_list = [ltb(btl(nonce+b'\x00\x00\x00\x02')+i).hex() for i in range(15, len(blocks_ct))]

data = ''.join(nonce_list)
print(data)



io.sendlineafter(b"Your choice > ", b"1")
io.sendlineafter(b"Please give me your message (in hex) > ", data)
ims = bytes.fromhex(io.recvline().rstrip().decode())
blocks_ims = [ims[i:i+16] for i in range(0, len(ims), 16)]


blocks_res = [xor(blocks_ct[i+15], blocks_ims[i]).hex() for i in range(len(blocks_ims))]

key = ''.join(blocks_res)
print(key)


io.sendlineafter(b"Your choice > ", b"3")
io.sendlineafter(b"Give me your secret (in hex) > ", key)



io.interactive()

