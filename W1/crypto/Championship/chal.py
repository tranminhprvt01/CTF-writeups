from Crypto.Util.number import *
import random
import math
from sympy.ntheory import discrete_log

p = getPrime(512)
q = getPrime(512)

phi = (p-1)*(q-1)
n = p*q
e = 17
assert GCD(e, phi) == 1
d = inverse(e, phi)

m = bytes_to_long(b'test')

s = pow(m, d, n)

print(s)

print(d)


assert pow(s, e, n) == m


def gen_smooth_prime(bits):
    factos = [2]
    prod = 2
    while prod.bit_length() < bits:
        r = getPrime(16)
        factos.append(r)
        prod*=r

    r = getPrime(20)
    while not isPrime(prod*r + 1):
        r = getPrime(20)
    factos.append(r)
    prod*=r
    assert math.prod(factos) == prod
    return prod+1, factos
    

n_fault, factos = gen_smooth_prime(1024)

print(n_fault)
print(factos)
print(isPrime(n_fault))

m_ = 2
s_ = pow(m_, d, n_fault)

print(s_)
print(m_)

def pohlig(h, g, p, factos):
    assert math.prod(factos)+1 == p
    res = []
    mods = []
    for i in factos:
        mod = i
        ord = (p-1)//i
        h_ = pow(h, ord, p)
        g_ = pow(g, ord, p)
        mods.append(mod)
        res.append(discrete_log(mod, h_, g_))
        print(res)
        print(mod)
    return res, mod



print(pohlig(s_, m_, n_fault, factos))



