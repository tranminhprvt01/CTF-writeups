#!/usr/bin/env python

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os

flag = os.environ['FLAG'].encode() if 'FLAG' in os.environ else b'justCTF{rrrbMer_yAwl4__krr4d_5i_yaD_n3w}'
iv = get_random_bytes(16)
key = get_random_bytes(16)

def padded(pt):
    pad_len = -len(pt) % 16
    return pt + bytes([pad_len]) * pad_len

while True:
    suffix = bytes.fromhex(input())

    plaintext = flag
    while len(suffix) and len(plaintext) and plaintext[-1] == suffix[0]:
        plaintext = plaintext[:-1]
        suffix = suffix[1:]
    #print(plaintext+suffix, padded(plaintext+suffix))
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    encrypted = cipher.encrypt(padded(plaintext + suffix))

    print(encrypted[-16:].hex())
