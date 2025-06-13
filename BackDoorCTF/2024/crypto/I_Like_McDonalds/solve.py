

from pwn import *
import string

alphabet = string.ascii_letters + string.digits + '{}'


#io = process(["python3", "server.py"])
io = remote('34.42.147.172', 8004)

temp = []

for i in alphabet:
    io.sendlineafter(b'Enter your message and token: ', f'{i.encode().hex()} 00')
    io.recvuntil(b'Invalid token! Expected token: ')
    temp.append((i.encode().hex(), io.recvline().rstrip().decode()))



for i in temp:
    io.sendlineafter(b'Enter your message and token: ', f'{i[0]} {i[1]}')
   




io.interactive()