from pwn import *
import time, sys, select
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.number import *
import ast



class RandomGenerator:
    def __init__(self, seed = None, modulus = 2 ** 32, multiplier = 157, increment = 1):
        if seed is None: 
            seed = time.asctime()
        if type(seed) is int: 
            self.seed = seed
        if type(seed) is str: 
            self.seed = int.from_bytes(seed.encode(), "big")
        if type(seed) is bytes: 
            self.seed = int.from_bytes(seed, "big")
        self.m = modulus
        self.a = multiplier
        self.c = increment

    def randint(self, bits: int):
        self.seed = (self.a * self.seed + self.c) % self.m
        result = self.seed.to_bytes(4, "big")
        while len(result) < bits // 8:
            self.seed = (self.a * self.seed + self.c) % self.m
            result += self.seed.to_bytes(4, "big")
        return int.from_bytes(result, "big") % (2 ** bits)

    def randbytes(self, len: int):
        return self.randint(len * 8).to_bytes(len, "big")




io = remote("tjc.tf", "31493")



io.recvuntil(b'Welcome to the AES Oracle\n')


seed = time.asctime()
print(seed)

randgen = RandomGenerator(seed)

io.recvuntil(b'ciphertext = ')
ct = ast.literal_eval(io.recvline().decode())
print(ct, len(ct), type(ct))



key = randgen.randbytes(32)
print(key)
print(AES.new(key, AES.MODE_ECB).decrypt(ct))

#io.interactive()