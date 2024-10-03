# nc wildwest.nc.jctf.pro 1337

from pwn import *
import hashlib
import string
from itertools import product
import math

io = remote("wildwest.nc.jctf.pro", 1337)

io.recvuntil(b'prefix: ')
prefix = io.recvline().rstrip().decode()

io.recvuntil(b'zero_length: ')
length = int(io.recvline().rstrip().decode())


for end in product(string.ascii_letters, repeat=20-len(prefix)):
    end = "".join(end)
    #print(end)
    combined = prefix + end 
    h = hashlib.sha256(combined.encode()).hexdigest()
    if h[:length] == "0"*length:
        print("Solved pow!")
        suffix = end
        print(suffix)
        break

io.recvuntil(b'sufix: ')
io.sendline(suffix)


def win(cur_round):
    for i in range(30-cur_round):
        io.recvuntil(b'balane: ')
        balance = int(io.recvline().rstrip().decode())
        io.sendlineafter(b"You suggest to bet:", str(1))



for _ in range(300):
    print(f"participant {_}")
    x = 0
    for i in range(1, 30):
        io.recvuntil(b'balane: ')
        balance = int(io.recvline().rstrip().decode())
        print(balance)
        num = int(((30-i)-0.8*x)//0.8)
        print(num)
        io.sendlineafter(b"You suggest to bet:", str(num))
        res = io.recvline().rstrip().decode()
        if res == 'Fail!':
            x+=num//2
        elif res == 'Success!':
            win(i)
            break


io.interactive()



