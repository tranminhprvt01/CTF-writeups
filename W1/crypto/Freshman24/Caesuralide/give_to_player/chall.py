from Crypto.Util.number import *
from itertools import*
from base64 import*
import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256
import os
with open('flag.txt', "rb") as f:
    flag = f.read()

first_half = flag[:len(flag)//2]
message = b64encode(first_half)
special_number = random.randint(0, 13**37)  # You are not supposed to have the special number
encrypted_message = [hex((i + special_number)%256)[2:] for i in message]

print(f"{encrypted_message = }")

second_half = flag[len(flag)//2:] # end with "v1ct0ry}"
shared_secret = 0

while shared_secret<1000000:
    a = random.randint(0, 100000)
    b = random.randint(0, 100000)
    G = 2
    shared_secret = GCD(G**a - 1, G**b - 1)

# Can you find the secret without any information?

def xor(a, b):
    return bytes([x ^ y for x, y in zip(a, cycle(b))])

key = SHA256.new(data=str(shared_secret).encode()).digest()[:128]
ct = xor(pad(second_half, 16), key).hex()
print(f"{ct = }")