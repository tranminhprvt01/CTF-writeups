import itertools

def small_roots(f, bounds, m=1, d=None):
	if not d:
		d = f.degree()

	if isinstance(f, Polynomial):
		x, = polygens(f.base_ring(), f.variable_name(), 1)
		f = f(x)

	R = f.base_ring()
	N = R.cardinality()
	
	#f /= f.coefficients().pop(0)
	f = f.change_ring(ZZ)

	G = Sequence([], f.parent())
	for i in range(m+1):
		base = N^(m-i) * f^i
		for shifts in itertools.product(range(d), repeat=f.nvariables()):
			g = base * prod(map(power, f.variables(), shifts))
			G.append(g)

	B, monomials = G.coefficient_matrix()
	monomials = vector(monomials)

	factors = [monomial(*bounds) for monomial in monomials]
	for i, factor in enumerate(factors):
		B.rescale_col(i, factor)

	B = B.dense_matrix().LLL()

	B = B.change_ring(QQ)
	for i, factor in enumerate(factors):
		B.rescale_col(i, 1/factor)

	H = Sequence([], f.parent().change_ring(QQ))
	for h in filter(None, B*monomials):
		H.append(h)
		I = H.ideal()
		if I.dimension() == -1:
			H.pop()
		elif I.dimension() == 0:
			roots = []
			for root in I.variety(ring=ZZ):
				root = tuple(R(root[var]) for var in f.variables())
				roots.append(root)
			return roots

	return []


M = 0x100000000000000000000000000000000
a = 0x570a9ec8b8a9e8005d20abb2e555e29d
x0 = 29186099369194997890922604909306052608
x1 = 96546435635255329419749944464313942016

P.<x, y> = PolynomialRing(Zmod(M))

f = a*(x0 + x) - (x1+y)

root = small_roots(f, [2^64, 2^64], 5, 5)
print(root)

root = root[0]

seed = x0 + root[0]

import random
from base64 import b64encode, b64decode
from Crypto.Util.number import *
from Crypto.Util.Padding import pad
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import random

class PRNG:
    def __init__(self):
        self.b = 128
        self.r = 64
        self.M = 2**self.b
        self.m = 2**self.r
        self.MULT = a
        self.INC = 0 
        self.SEED = int(seed)

    def getval(self):
        return (self.SEED - self.SEED % self.m, self.MULT, self.M)

    def next(self):
        self.SEED = ((self.SEED * self.MULT) + self.INC) % self.M
        return self.SEED



h = []
prng = PRNG()
SEED_MSB, MULT, M = prng.getval()
h.append(SEED_MSB)
print(h)



print(f"[*] MULT : {hex(MULT)}")
print(f"[*] M : {hex(M)}")


for i in range(2):
    prng.next()
    h.append(prng.getval()[0])

key = int(prng.next()).to_bytes(16, byteorder='big')

print(h)

res = {'iv': '/5E2ciAHa0oGBEkIzoRV1A==', 'ciphertext': '+huZfkhjnNtH4sxZrItOxbJmu3RvMyOfNQH69axnX/nQcEw2iwTrZRgZyzbL8FoGB7uE5nEm2WLl8ZK5HFBCuq0ZaVv/u17pAJ23dHBqtA7Dp1hdj/gHjR6Ja+Ok7d4G5oPnMfN6xd79uuKjzwgt4w=='}


def decrypt(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext


print(decrypt(b64decode(res['ciphertext'].encode()), key, b64decode(res['iv'].encode())))
