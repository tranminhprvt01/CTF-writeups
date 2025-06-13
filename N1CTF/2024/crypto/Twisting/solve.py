from Crypto.Cipher import AES
from Crypto.Util.strxor import strxor
from Crypto.Util.number import *
from Crypto.Cipher._mode_gcm import _GHASH, _ghash_portable as ghash_c
import os


FLAG = "n1ctf{faker_flag}"

block_size = 16
pad = lambda X: b'\x00'*(block_size-len(X)%block_size)+X
"""
class Oracle:
    def __init__(self):
        self.key, self.nonce = os.urandom(16), os.urandom(12)
        self.H1 = AES.new(self.key, AES.MODE_ECB).encrypt(b'\x00'*16)
        self.H2 = AES.new(self.key, AES.MODE_ECB).encrypt(b'\x01'*16)
        
    def h(self, a, b, H):
        print("init check of h", a, b, H)
        print(long_to_bytes(len(b), 8))
        l = long_to_bytes(len(a), 8)+long_to_bytes(len(b), 8)
        print(l)
        a, b = pad(a), pad(b)
        print(a)
        print(b)
        return _GHASH(H, ghash_c).update(a+b+l).digest()
    
    def encrypt(self, msg, k):
        A, B = msg[:block_size], msg[block_size:]
        S = strxor(AES.new(self.key, AES.MODE_ECB).encrypt(A), self.h(B, k, self.H1))
        print("Check S", S)
        E = AES.new(S, AES.MODE_CTR, nonce=self.nonce).encrypt(B)
        G = AES.new(self.key, AES.MODE_ECB).decrypt(strxor(S, self.h(E, k, self.H2)))
        return G.hex(), E.hex(), k.hex()
        
    def decrypt(self, cipher, k):
        G, E = cipher[:block_size], cipher[block_size:]
        S = strxor(AES.new(self.key, AES.MODE_ECB).encrypt(G), self.h(E, k, self.H2))
        B = AES.new(S, AES.MODE_CTR, nonce=self.nonce).decrypt(E)
        A = AES.new(self.key, AES.MODE_ECB).decrypt(strxor(S, self.h(B, k, self.H1)))
        return A.hex(), B.hex()


K = []
sys = Oracle()
k_ = os.urandom(16)
print("🚩", sys.encrypt(f"your flag: {FLAG}".encode(), k_))
for _ in "Nu1L":
    op = input("> ")
    k = bytes.fromhex(input(">> "))
    data = bytes.fromhex(input(">>> "))
    if k not in K:
        K.append(k)
        if op == 'E':
            print(sys.encrypt(data, k))
        elif op == 'D' and k != k_:
            print(sys.decrypt(data, k))
    else:
        print("Hacker?")
"""


def h(a, b, H):
        print("init check of h", a, b, H.hex())
        print(long_to_bytes(len(b), 8))
        l = long_to_bytes(len(a), 8)+long_to_bytes(len(b), 8)
        print(l, "dis l")
        a, b = pad(a), pad(b)
        print(a)
        print(b)
        print(a+b+l, "payload", len(a+b+l))
        return _GHASH(H, ghash_c).update(a+b+l).digest()


key, nonce = os.urandom(16), os.urandom(12)
print(key.hex())
print(nonce.hex())

H1 = AES.new(key, AES.MODE_ECB).encrypt(b'\x00'*16)
H2 = AES.new(key, AES.MODE_ECB).encrypt(b'\x01'*16)


print(H1.hex())
#print(H2.hex())


A = b'\x00'*16
B = b'\x00'*16
k = b'\x00'*16

h_ = h(B, k, H1)

print(h_)



S = strxor(AES.new(key, AES.MODE_ECB).encrypt(A), h_)

print(S, "S")



l = long_to_bytes(len(B), 8)+long_to_bytes(len(k), 8)
a = pad(B)
b = pad(k)

print(len(a+b+l))

g_hash = _GHASH(H1, ghash_c)
g_hash.update(a+b+l)
print(g_hash.digest())



l = long_to_bytes(bytes_to_long(l[::-1])+128, 16)[::-1]

print(a+b+l, "new payload", len(a+b+l))
g_hash = _GHASH(H1, ghash_c)


g_hash.update(a+b+l)
print(g_hash.digest())


# print(strxor(H1, h_))