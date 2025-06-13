#nc ctf.mf.grsu.by 9027

from pwn import *

io = remote("ctf.mf.grsu.by", 9027)


def xuli(s):
    res = ""
    if len(s) == 1 and s == "x": return "1"
    for i in s:
        if i != "*":
            res+=i
        else:
            return res



for i in range(50):
    if i % 10 == 0:
        io.recvuntil(b'Elliptic Curve defined by Ep(a,b): ')
        data = io.recvline().rstrip().decode().split()

        print(data)

        E = EllipticCurve(GF(int(data[-1])), [int(xuli(data[4])), int(data[6])])

        print(E)
    io.recvuntil(b'P = ')
    data = io.recvline().rstrip().decode().split()
    print(data)
    x, y = int(data[0][1:-1]), int(data[1][:-1])

    try:
        P = E(x, y)
        print(P)

        data = io.recvline().rstrip().decode().split()
        print(data)
        k = int(xuli(data[0]))
        print(k, P.order())
        print(k % P.order())

        Q = k*P
        print(Q)
        io.sendline(f"{Q.xy()[0]}, {Q.xy()[1]}")
    except:
        io.sendline("None")



io.interactive()