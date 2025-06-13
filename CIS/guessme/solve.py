from sage.all import *
from secp256k1 import *
import secrets
from hashlib import sha256
# from flag import FLAG
import json
from pwn import *

def gen_publickey(a, gen_proof=False):  # generate public key with a Schnorr proof
    # A = multiply(G, a)
    A = cast("PlainPoint2D", (0, 1))
    if gen_proof:
        k = secrets.randbelow(N)
        R = multiply(G, k)
        e = int(sha256((str(P) + str(Gx) + str(Gy) +
                str(A[0]) + str(A[1]) + str(R[0]) + str(R[1])).encode()).hexdigest(), 16)
        z = (e * a + k) % N
        print(add(multiply(A, e), R))
        print(R)
        print(multiply(G, z))
        print(z)
        print(k)
        print('-' * 50)
        assert multiply(G, z) == add(multiply(A, e), R)
        print("hehe")
        return A, (R, z)
    return A


def verify_publickey(A, proof):
    R, z = proof
    e = int(sha256((str(P) + str(Gx) + str(Gy) +
            str(A[0]) + str(A[1]) + str(R[0]) + str(R[1])).encode()).hexdigest(), 16)
    return multiply(G, z) == add(multiply(A, e), R)

# while True:
#     try:
#         A, proof = gen_publickey(0, True)
#         print(A, proof)
#     except:
#         pass



context.log_level = 'DEBUG'

P = 2**256 - 2**32 - 977
N = 115792089237316195423570985008687907852837564279074904382605163141518161494337
a = 0
b = 7
Gx = 55066263022277343669578718895168534326250603453777594175500187360389116729240
Gy = 32670510020758816978083085130507043184471273380659243275938904335757337482424

E = EllipticCurve(GF(P), [a, b])
# print(E.lift_x(GF(P)(52260279946305198560105122982203470159747965204813603478087545996882636086090), all=True))

bit0 = json.dumps({'bit': 0})
bit1 = json.dumps({'bit': 1})

R = cast("PlainPoint2D", (17426422564000603146918447714980024995309380167098109228746536175038042516889, 10954778723299001636409026230130668839703115977382347846699621718503982172815))
z = 72127871402049747546561459772651810256818657017856405914675197240242667856279
A = cast("PlainPoint2D", (0, 1))
proof = (R, z)
assert verify_publickey(A, (R, z))

with remote("103.173.227.108", "10001") as io:
# with process(["python3", "chall.py"]) as io:
    for i in range(128):
        print(i)
        io.sendlineafter(b"proof.\n", json.dumps({"publickey": A, "proof": proof}).encode())
        io.recvuntil(b"B = ")
        point = eval(io.recvline().strip().decode())
        points = E.lift_x(GF(P)(point[0]), all=True)
        check = False
        for i in points:
            if int(point[1]) == int(i.xy()[1]):
                check = True
                io.sendlineafter(b'bit.\n', bit0.encode())
                break
        if not check:
            io.sendlineafter(b'bit.\n', bit1.encode())
    io.interactive()