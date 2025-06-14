import random
from secrets import randbelow, randbits
from Crypto.Util.number import inverse as inv
#from flag import FLAG
FLAG = b'sekai{fake_flag}'

CIPHER_SUITE = randbelow(2**256)
print(f"oPUN_SASS_SASS_l version 4.0.{CIPHER_SUITE}")
random.seed(CIPHER_SUITE)

GSIZE = 8209
GNUM = 79

LIM = GSIZE**GNUM


def gen(n):
    p, i = [0] * n, 0
    for j in random.sample(range(1, n), n - 1):
        p[i], i = j, j
    return tuple(p)


def gexp(g, e):
    res = tuple(g)
    while e:
        if e & 1:
            res = tuple(res[i] for i in g)
        e >>= 1
        g = tuple(g[i] for i in g)
    return res


def enc(k, m, G):
    if not G:
        return m
    mod = len(G[0])
    return gexp(G[0], k % mod)[m % mod] + enc(k // mod, m // mod, G[1:]) * mod


def inverse(perm):
    res = list(perm)
    for i, v in enumerate(perm):
        res[v] = i
    return res


G = [gen(GSIZE) for i in range(GNUM)] #random 79 permutations from 0 -> Gsize-1

print(LIM, LIM.bit_length())

FLAG = int.from_bytes(FLAG, 'big')
print(FLAG, bin(FLAG), FLAG.bit_length())
left_pad = randbits(randbelow(LIM.bit_length() - FLAG.bit_length()))
print(left_pad)
FLAG = (FLAG << left_pad.bit_length()) + left_pad
print(FLAG, bin(FLAG), FLAG.bit_length())
FLAG = (randbits(randbelow(LIM.bit_length() - FLAG.bit_length()))
        << FLAG.bit_length()) + FLAG
print(FLAG, bin(FLAG), FLAG.bit_length(), "flag")

bob_key = randbelow(LIM)
print("bob key, debug", bob_key)
bob_encr = enc(FLAG, bob_key, G)
print("bob says", bob_encr)
alice_key = randbelow(LIM)
print("alice key, debug", alice_key)
alice_encr = enc(bob_encr, alice_key, G)
print("alice says", alice_encr)
bob_decr = enc(alice_encr, bob_key, [inverse(i) for i in G])
print("bob says", bob_decr)


#print(G[0])



bob_key = enc(alice_encr, bob_decr, G)
print(bob_key, "recover bob_key")
alice_key = enc(bob_encr, alice_encr, [inverse(i) for i in G])
print(alice_key, "recover alice_key")




print(enc(bob_decr, inv(bob_key, GSIZE), [inverse(i) for i in G]))
