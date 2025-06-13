from pwn import *
from Crypto.Util.number import long_to_bytes as ltb

io = remote("challs.actf.co", "31300")


for i in range(64):
    io.recvuntil(b'pubkey: ')
    n = int(io.recvline().rstrip().decode())

    io.recvuntil(b'plaintext: ')
    m_ = int(io.recvline().rstrip().decode())

    c = pow(m_, 2, n)

    P.<x> = PolynomialRing(Zmod(n))

    f = x^2 - c

    r = f.small_roots(X = 2^128)

    print(r)

    for root in r:
        print(root)
        if int(root).bit_length() <= 128:
            print(root)
            io.sendlineafter(b"gimme the secret: ", ltb(int(root)).hex())




io.interactive()




io.interactive()
