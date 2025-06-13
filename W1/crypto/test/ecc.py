from collections import namedtuple
from Crypto.Util.number import * 
from sympy import *

flag = b'HCMUS-CTF{?????????????????????????????????????????????????????????????}'

Point = namedtuple("Point", "x y")

p = 6893376086386561419838698019210625084105072958198117999188909127826231590566448000174970579911428646393945662110990534292897268475809055737928022920902197
q = 12162077535424750708584517429237281311914148704019342612036347617155291306759164051529085041163989963340832656121632723930574603217881811261623740854946731

# Public
n = p * q 
a = 0
b = 1

def dbl(P1: Point) -> Point:
    X1, Z1 = P1

    XX = X1**2 % n
    ZZ = Z1**2 % n
    A = 2 * ((X1 + Z1) ** 2 - XX - ZZ) % n
    aZZ = a * ZZ % n
    X3 = ((XX - aZZ) ** 2 - 2 * b * A * ZZ) % n
    Z3 = (A * (XX + aZZ) + 4 * b * ZZ**2) % n

    return (X3, Z3)

def diffadd(P1: Point, P2: Point, x0: int) -> Point:
    X1, Z1 = P1
    X2, Z2 = P2
    X1Z2 = X1 * Z2 % n
    X2Z1 = X2 * Z1 % n
    Z1Z2 = Z1 * Z2 % n
    T = (X1Z2 + X2Z1) * (X1 * X2 + a * Z1Z2) % n
    Z3 = (X1Z2 - X2Z1) ** 2 % n
    X3 = (2 * T + 4 * b * Z1Z2**2 - x0 * Z3) % n
    return (X3, Z3)

def swap(bit: int, P1: Point, P2: Point) -> tuple[Point, Point]:
    if bit == 1:
        P1, P2 = P2, P1
    return P1, P2

def scalarmult(scalar: int, x0: int) -> int:
    R0 = Point(x0, 1)
    R1 = dbl(R0)
    m = scalar.bit_length()
    pbit = 0
    for i in range(m - 2, -1, -1):
        bit = (scalar >> i) & 1
        pbit = pbit ^ bit
        if pbit:
            R0, R1 = R1, R0
        R1 = diffadd(R0, R1, x0)
        R0 = dbl(R0)
        pbit = bit
    if bit:
        R0 = R1
    return R0[0] * inverse(R0[1], n) % n
    
def is_square(a: int, p: int) -> bool: 
    return pow(a, (p - 1) // 2, p) == 1 

def pad(msg: bytes) -> int: 
    msg += b'\0' * ((n.bit_length() + 7) // 8 - len(flag))
    msg = bytes_to_long(msg)
    assert msg < n, "Wack O_O"
    return msg 

def encrypt(msg: bytes, e: int) -> bytes: 
    msg = pad(msg)
    while not (is_square((msg ** 3) + 1, p) and is_square((msg ** 3) + 1, q)): 
        msg += 1  
    enc = scalarmult(e, msg)
    return long_to_bytes(enc) 

def decrypt(msg: bytes) -> bytes:
    raise NotImplementedError

enc = encrypt(flag, 2)

print(enc)

# b'f-l\x1d\t_\xc56D\x1d\xf1\xf2\xa5\xfd\xb4\x83`\x03\xb2\xd8\xa2\x1c\x88\xee\xbe\x9a\x98BFPd-:\xc3\xb8\xa0\x13u\xe7\xc1TQv;\x9e\x07\xd3u\xa5O!;\xc4\xcc\\\xf9\x11Q\xce\x85=qdW\xa6]\xd7KPE\xa9\x90\x88\xc2.Cp\xec\xfd+H9?\x03\xb9F\xd7\xde\x14kG\x90d\xca\xed<\xca\t\xb2\xd1\xd9*\x87;$BG\xb0\xabE\xbd\x9bTR%\x9cE\xbe\x88,\xd4\x9a\x9f\xba\x9f\xa0\xc2\xeb'