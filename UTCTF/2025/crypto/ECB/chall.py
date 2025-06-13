# nc challenge.utctf.live 7150
#!/usr/bin/env python3

import os #test
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
key = os.urandom(16)#open("/src/key", "rb").read()
secret = "utflag{test_flag}"#open("/src/flag.txt", "r").read()
cipher = AES.new(key, AES.MODE_ECB)

while 1:
    print('Enter text to be encrypted: ', end='')
    x = input()
    chksum = sum(ord(c) for c in x) % (len(x)+1)
    pt = x[:chksum] + secret + x[chksum:]
    ct = cipher.encrypt(pad(pt.encode('utf-8'), AES.block_size))
    print(hex(int.from_bytes(ct, byteorder='big')))