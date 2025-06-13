from pwn import *
from Crypto.Cipher import AES
from Crypto.Util.number import *
from tqdm import tqdm
from hashlib import md5

import sys
sys.set_int_max_str_digits(0)




ns = []
cs = []

io = remote("key-in-a-haystack.chal.uiuc.tf", 1337, ssl=True)

io.recvuntil(b'enc_flag: ')
ct = bytes.fromhex(io.recvline().rstrip().decode())
cs.append(ct)
io.recvuntil(b'haystack: ')
n = int(io.recvline().rstrip().decode())
ns.append(n)
io.close()


print(n.bit_length())


while True:
    io = remote("key-in-a-haystack.chal.uiuc.tf", 1337, ssl=True)
    io.recvuntil(b'enc_flag: ')
    ct = bytes.fromhex(io.recvline().rstrip().decode())
    cs.append(ct)
    io.recvuntil(b'haystack: ')
    n = int(io.recvline().rstrip().decode())
    #print(x)
    for j in range(len(ns)):
        x = GCD(ns[j], n)
        if ns[j] % x == 0:
            ns[j] //= x
    ns.append(n)
    print(len(ns))
    """
    for n in ns:
        print(n.bit_length())
    """
    print(ns[0].bit_length())
    if ns[0].bit_length() == 40:
        print("Done eliminating")
        key = ns[0]
        break


print(key)

flag = AES.new(
	key = md5(b"%d" % key).digest(),
	mode = AES.MODE_ECB
).decrypt(cs[0])


print(flag)



# uiuctf{Finding_Key_Via_Small_Subgroups}



io.interactive()
