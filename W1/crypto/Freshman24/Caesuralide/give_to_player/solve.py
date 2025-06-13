from Crypto.Util.number import *
from itertools import*
from base64 import*

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256



alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="



encrypted_message = ['f', '33', 'ff', 'f0', '12', '33', 'fb', '2d', '12', '23', 'ff', '2e', '6', '10', 'ee', '27', '11', 'eb', 'e9', '31', '1b', '0', '25', 'e9', '12', '11', '3', 'ee', '11', '33', 'f', 'e9', '1c', '23', 'b', 'e9', '6', 'eb', '1d', 'ee', '11', 'ec', '1c', '31', '1d', '0', '21', '1f', '1a', 'eb', 'ed', '30', '1d', '30', 'f6', 'f6']

known = b64encode(b'W1{')
for num in range(256):
    if [hex((i + num)%256)[2:] for i in known] == encrypted_message[:len(known)]:
        print("Found num", num)
        sec_num = num


flag = []
for i in range(len(encrypted_message)):
    for chr in alphabet:
        if hex((chr + sec_num)%256)[2:] == encrypted_message[i]:
            flag.append(bytes([chr]))


f_flag = b''.join(flag)

print(b64decode(f_flag))


ct = bytes.fromhex('9fb4a30164fabcbb2de05e86a222c8ee42a5d9c3d7f66e4b85039f9b07061c86aca7f6057595a2a764832aded115909d')



def xor(a, b):
    return bytes([x ^ y for x, y in zip(a, cycle(b))])

import math
from tqdm import tqdm

import sys

sys.set_int_max_str_digits(10**6)


for shared_secret in tqdm(range(100000)):
    key = SHA256.new(data=str((1<<shared_secret)-1).encode()).digest()[:128]
    s_flag = xor(ct, key)
    try:
        s_flag = unpad(s_flag, 16)
        if s_flag.endswith(b"v1ct0ry}"):
            print("FOUND share", shared_secret)
            #print(s_flag)
            break
    except:continue


print(b64decode(f_flag) + s_flag)


