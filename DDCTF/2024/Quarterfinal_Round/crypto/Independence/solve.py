from Crypto.Util.number import *

f = open('out.txt', 'r')
pub = eval(f.readline()[5:])
g, p = pub
out = eval(f.readline()[5:])
print(len(out))

print(p, p%4)


def encrypt(m, pubkey, privkey):
    g, p = pubkey
    x, _ = privkey
    h = pow(g, x, p)
    C = []
    while m:
        print(m, m&1)
        y = getRandomRange(2, p)
        c1 = pow(g, y, p)
        y = (y<<1) | (m & 1)
        c2 = pow(h, y, p)
        C += [(c1, c2)]
        m >>= 1
        print(pow(c2, (p-1)//2, p))
        print("~"*40)
    return C

def keygen(nbits=512):
    p = getStrongPrime(nbits)
    g = getRandomRange(2, p)
    x = getRandomRange(2, p)
    pub = (g, p)
    priv = (x, p)
    return pub, priv

pub, priv = keygen()
print(encrypt(19, pub, priv))


"""
flag = ''
for c in out:
    if pow(c[1], (p-1)//2, p) == 1:flag+='0'
    else: flag+='1'

flag = flag[::-1]

flag = int(flag, 2)
print(long_to_bytes(flag))
"""


