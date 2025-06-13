from pwn import xor
from random import randint
from hashlib import sha256


cc = [randint(-2**67, 2**67) for _ in range(9)]
key = sha256("".join(str(i) for i in cc).encode()).digest()


print(cc)
print("".join(str(i) for i in cc))