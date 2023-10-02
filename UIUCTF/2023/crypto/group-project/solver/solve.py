from pwn import *
from Crypto.Util.number import *
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


host, port = "group.chal.uiuc.tf", 1337

r = remote(host, port)



r.recvuntil(b"[$] Did no one ever tell you to mind your own business??\n")

r.recvuntil(b"[$] Public:\n")




g = int(r.recvline().rstrip()[12:])
p = int(r.recvline().rstrip()[12:])
A = int(r.recvline().rstrip()[12:])

r.recvuntil(b"[$] Choose k = ")
r.sendline(str((0)))

r.recvuntil(b"[$] Ciphertext using shared 'secret' ;)\n")

S = 1

c = int(r.recvline().rstrip()[12:])

key = hashlib.md5(long_to_bytes(S)).digest()
cipher = AES.new(key, AES.MODE_ECB)

flag = cipher.decrypt(long_to_bytes(c))

print(flag)

r.interactive()

