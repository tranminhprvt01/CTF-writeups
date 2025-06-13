#nc 20.255.51.113 5000
from hashlib import *
from Crypto.Util.Padding import pad

FLAG = open('flag.txt', 'rb').read()

assert len(FLAG) == 16

def md5Hash(block):
    return md5(block).digest()

def encrypt(plaintext):
    ct = b''
    pt = pad(plaintext + FLAG, 16)
    for i in range(0, len(pt), 16):
        ct += md5Hash(pt[i:i + 16])

    return ct.hex()

attemps = 5000
tries = 0
while True:
    if tries > attemps:
        print("You lose!")
        exit(0)

    plaintext = bytes.fromhex(input('Plaintext > ').strip())
    print("enc >", encrypt(plaintext))
    tries += 1
