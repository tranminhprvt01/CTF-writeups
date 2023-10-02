from pwn import *

host, port = "morphing.chal.uiuc.tf", 1337

r = remote(host, port)

r.recvuntil(b"[$] Public:\n")

g = int(r.recvline().rstrip()[12:])
p = int(r.recvline().rstrip()[12:])
A = int(r.recvline().rstrip()[12:])

r.recvuntil(b"[$] Eavesdropped Message:\n")
c1 = int(r.recvline().rstrip()[13:])
c2 = int(r.recvline().rstrip()[13:])



r.recvuntil(b"[$] Give A Ciphertext (c1_, c2_) to the Oracle:\n")

c1_ = 2
c2_ = 2


from Crypto.Util.number import *

r.sendline(str(c1_))
r.sendline(str(c2_))

r.recvuntil(b"[$] Decryption of You-Know-What:\n")

m = int(r.recvline().rstrip()[12:])



print(m)

flag = m*inverse(2, p) * A % p

print(flag)
print(long_to_bytes(flag))

r.interactive()

