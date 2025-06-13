from pwn import *


def expand(ls):
    return [f[0] for f in ls for i in range(f[1])]

while True:
    io = remote('65.109.192.143', '13731')


    io.recvuntil(b'p = ')
    p = int(io.recvline().rstrip().decode())

    factos = expand(list(factor(p-1)))


    if len(set(factos)) == 7 == len(factos):
        break


print(p)
print(factos, len(factos))




io.interactive()