from pwn import *
from Crypto.Util.number import long_to_bytes as ltb, bytes_to_long as btl



import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../lattice-based-cryptanalysis'))


from lbc_toolkit import ecdsa_biased_nonce_known_msb




io = remote("154.26.136.227", "46475")#process(["python", "chall.py"])


p = 0x01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff 
a, b = 0x01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc, 0x0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00

n = 0x01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409
E = EllipticCurve(GF(p), [a, b])

G = E(0x00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66, 0x011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650)


l, ell = 9, 98
print(f'ECDSA biased nonce known MSB attack with l = {l}, ell = {ell}')
Z, R, S, T = [], [], [], []


h = lambda x: hashlib.sha512(x).digest()


def inv(n, q):
    return egcd(n, q)[0] % q

def egcd(a, b):
    s0, s1, t0, t1 = 1, 0, 0, 1
    while b > 0:
        q, r = divmod(a, b)
        a, b = b, r
        s0, s1, t0, t1 = s1, s0 - q * s1, t1, t0 - q * t1
        pass
    return s0, t0, a


from tqdm import tqdm

for i in tqdm(range(ell)):
    io.sendlineafter(b'> ', '1')
    m = os.urandom(4)
    io.sendlineafter(b'Give me da message in hex: ', m.hex())
    io.recvuntil(b'Here is your signature: ')
    sig = eval(io.recvline().rstrip())
    r, s = sig
    # print(r)
    # print(s)
    z = btl(h(m))
    # print(z)
    t = 0
    Z.append(ZZ(z)); R.append(ZZ(r)); S.append(ZZ(s)); T.append(ZZ(t))


d = ecdsa_biased_nonce_known_msb(Z, R, S, T, n, l)
print(d)

m = b'get flag'

z = h(m)
k = btl(h(h(ltb(d))+z))%n
P = G*k

r = int(P.xy()[0]) % n
s = int(inv(k, n) * (btl(z) + r*d))%n

io.sendlineafter(b'> ', '2')
io.sendlineafter(b'r: ', str(r))
io.sendlineafter(b's: ', str(s))



io.interactive()
