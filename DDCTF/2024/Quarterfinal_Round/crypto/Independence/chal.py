from Crypto.Util.number import *

FLAG = open('flag.txt', 'rb').read()

def encrypt(m, pubkey, privkey):
    g, p = pubkey
    x, _ = privkey
    h = pow(g, x, p)
    C = []
    while m:
        y = getRandomRange(2, p)
        c1 = pow(g, y, p)
        y = (y<<1) | (m & 1)
        c2 = pow(h, y, p)
        C += [(c1, c2)]
        m >>= 1
    return C

def keygen(nbits=512):
    p = getStrongPrime(nbits)
    g = getRandomRange(2, p)
    x = getRandomRange(2, p)
    pub = (g, p)
    priv = (x, p)
    return pub, priv

pub, priv = keygen()
m = bytes_to_long(FLAG)
c = encrypt(m, pub, priv)

with open('out.txt', 'w') as f:
    f.write(f'{pub = }\n')
    f.write(f'out = {str(c)}')
