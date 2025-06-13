from Crypto.Util.number import getPrime
from hashlib import sha256

import socketserver
import signal
import random
import string


class FNV():
    def __init__(self):
        self.pbit = 1024
        self.p = getPrime(self.pbit)
        self.key = random.randint(0, self.p)
    
    def H4sh(self, value:str):
        length = len(value)
        print(length)
        x = (ord(value[0]) << 7) % self.p
        print(x)
        for c in value:
            x = ((self.key * x) % self.p) ^ ord(c)
        

        print(x)
        x ^= length
        
        return x



str_table = string.ascii_letters + string.digits


print(str_table, len(str_table))


fnv = FNV()

n = 32
cnt = 67

sample = ''.join(random.choices(str_table, k=n))

print(sample, len(sample))


print(fnv.H4sh(sample))