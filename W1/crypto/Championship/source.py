# HNP problem

import random
import hashlib
from Crypto.Util.number import *


q = getPrime(256)
while not isPrime(2*q+1):
    q = getPrime(256)
p = 2*q+1

print(p.bit_length())
print(q.bit_length())

print(f"{p = }")
print(f"{q = }")

h = random.randint(2, p-2)
g = pow(h, 2, p)
print(f"{g = }")



x = random.randint(1, q-1)
y = pow(g, x, p)


print(f"{x = } priv")
print(f"{y = } pub")




class LCG():
    def __init__(self, seed):
        self.p = q
        self.a = 0x123456
        self.c = 0x654321
        self.seed = seed
    def next(self):
        self.seed = self.a*self.seed + self.c
        self.seed %= self.p
        return self.seed


lcg = LCG(random.randint(1, q-1))


print(lcg.next())
print(lcg.next())

def sign(m:bytes):
    h = bytes_to_long(hashlib.md5(m).digest())
    k = lcg.next()
    print(k, "cur nonce")
    r = pow(g, k, p) % q
    s = (inverse(k, q) * (h+x*r)) % q

    return r, s



m1 = b'this is temp message'
r, s = sign(m1)


print(r)
print(s)



def verify(m, r, s):
    assert 0 < r < q, "Wrong value"
    assert 0 < s < q, "Wrong value"
    h = bytes_to_long(hashlib.md5(m).digest())

    w = inverse(s, q)
    u1 = (h * w) % q
    u2 = (r * w) % q
    v = ((pow(g, u1, p) * pow(y, u2, p))%p) % q

    return v == r



print(verify(m1, r, s))




m2 = b"Another temp message for test"


r2, s2 = sign(m2)

print(r2)
print(s2)




