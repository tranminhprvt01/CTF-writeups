from pwn import *
import time
import random

io = remote("challenge.nahamcon.com", "32002")
random.seed(int(time.time())+1)
io.recvuntil(b'The encrypted flag is: ')
ct = bytes.fromhex(io.recvline().rstrip().decode())

key = bytes(random.randint(0, 255) for _ in range(len(ct)))

print(xor(ct, key))



io.interactive()