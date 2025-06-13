#nc ctf.mf.grsu.by 9016

from pwn import *
from base64 import b64encode, b64decode

io = remote("ctf.mf.grsu.by", 9016)

io.recvuntil(b'secret ciphertext (b64): ')
ct = b64decode(io.recvline().rstrip())
print(len(ct))


flag = ""
alphabet = "etoanihsrdlucgwyfmpbkvjxqz{}_01234567890ETOANIHSRDLUCGWYFMPBKVJXQZ"

tmp = b64encode(b'A'*47)
io.sendline(tmp.decode())
io.recvuntil(b'ciphertext (b64): ')
tmp_ct = b64decode(io.recvline().rstrip())
print(len(tmp_ct))

check = tmp_ct[32:48]



while True:

    for i in alphabet:
        payload = 'A'*(48-len(flag)-1) + flag + i
        print(payload, 'brute')
        inp = b64encode(payload.encode())
        io.sendline(inp.decode())
        io.recvuntil(b'ciphertext (b64): ')
        tmp_inp = b64decode(io.recvline().rstrip())
        if tmp_inp[32:48] == check:
            print("Found with", i)
            flag += i
            break
    
    payload = 'A'*(48-len(flag)-1)
    print(payload, 'init')
    tmp = b64encode(payload.encode())
    io.sendline(tmp.decode())
    io.recvuntil(b'ciphertext (b64): ')
    tmp_ct = b64decode(io.recvline().rstrip())
    print(len(tmp_ct))

    check = tmp_ct[32:48]



    if flag.endswith('}'):
        break






io.interactive()

#grodno{d45870AES_1n_ECB_m0de_1s_hackabledf3ae3}