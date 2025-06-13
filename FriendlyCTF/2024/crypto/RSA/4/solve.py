from Crypto.Util.number import *
import math
from gmpy2 import iroot
from sympy.ntheory.modular import crt

import sys

sys.set_int_max_str_digits(10**5)

# Load my friends keys
moduli = []
with open("keys.txt", "r") as f:
    moduli = [int(line.strip()) for line in f.readlines()]


ct = []
with open("ciphertexts.txt", "r") as f:
    ct = [int(line.strip()) for line in f.readlines()]


for i in range(len(moduli[:17])-1):
    for j in range(i+1, len(moduli[:17])):
        if GCD(moduli[i], moduli[j]) != 1:
            print("Fail")


n_ = math.prod(moduli[:17])
c_ = crt(moduli[:17], ct[:17])[0]
print(c_)
m = iroot(c_, 17)
print(m)
print(long_to_bytes(m[0]))