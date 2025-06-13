from pwn import *

io = process(["python", "server.py"])


io.recvuntil(b'p = ')
p = int(io.recvline().rstrip().decode())

io.sendlineafter(b'Enter option: ', b'1')

io.recvuntil(b'coefficients = ')
coeff = eval(io.recvline().rstrip().decode())

io.sendlineafter(b'Enter message: ', b'hehe')

io.interactive()