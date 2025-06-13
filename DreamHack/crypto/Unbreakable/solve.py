from hashlib import sha256
import os
import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


TOTAL_BITS = 624 * 37
def challenge(num_bit, previous, current):
    random.seed(os.urandom(16))
    num_task = (TOTAL_BITS + num_bit - 1) // num_bit

    output = ""
    for _ in range(num_task):
        output += format(random.getrandbits(num_bit), f"0{num_bit}b")
    
    print(output)

    key = previous
    for _ in range(100):
        key += format(random.getrandbits(num_bit), f"0{num_bit}b").encode()
        key = sha256(key).digest()
    
    cipher = AES.new(key, AES.MODE_CBC, iv=b'iluvredblacktree')
    print(cipher.encrypt(pad(current, 16)).hex())


print(challenge(32, b'iloveredblacktree', ))