from base64 import b64encode, b64decode
from Crypto.Util.number import *
from Crypto.Util.Padding import pad
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import random
from secret import flag

class PRNG:
    def __init__(self):
        self.b = 128
        self.r = 64
        self.M = 2**self.b
        self.m = 2**self.r
        self.MULT = random.randint(0, self.M)
        self.INC = 0 
        self.SEED = random.randint(0, self.M)

    def getval(self):
        return (self.SEED - self.SEED % 2**self.r, self.MULT, self.M)

    def next(self):
        self.SEED = ((self.SEED * self.MULT) + self.INC) % self.M
        return self.SEED

def encrypt(flag, key): 
    cipher = AES.new(key, AES.MODE_CBC)
    ct = cipher.encrypt(pad(flag, AES.block_size))
    iv = b64encode(cipher.iv).decode("utf-8")
    ciphertext = b64encode(ct).decode("utf-8")
    return {"iv": iv, "ciphertext": ciphertext}

def decrypt(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext

h = []
prng = PRNG()
SEED_MSB, MULT, M = prng.getval()
h.append(SEED_MSB)

print(f"[*] MULT : {hex(MULT)}")
print(f"[*] M : {hex(M)}")

for i in range(2):
    prng.next()
    h.append(prng.getval()[0])

key = (prng.next()).to_bytes(16, byteorder='big')

print(encrypt(flag, key))
print(f"high order bits : {h}")
