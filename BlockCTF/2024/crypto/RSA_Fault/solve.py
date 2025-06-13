from pwn import *
from Crypto.Util.number import *

io = remote("54.85.45.101", 8010)



n = 30392456691103520456566703629789883376981975074658985351907533566054217142999128759248328829870869523368987496991637114688552687369186479700671810414151842146871044878391976165906497019158806633675101
e = 65537

c = randint(1, 1<<24)
print(c)


io.sendlineafter(b'Send your ciphertext in hex format:\n', b'flag')
io.recvuntil(b'Encrypted flag (hex): ')
ct = int(io.recvline().rstrip(), 16)
print(ct)


while True:
    io.sendlineafter(b'Send your ciphertext in hex format:\n', f"{c:x}")
    io.recvuntil(b'Decrypted message (hex): ')
    sig = int(io.recvline().rstrip().decode(), 16)
    check = io.recvline()
    print(check)
    if check == b"Note: Fault occurred during decryption.\n":
        print("FAULT ocurred")
        break
    elif check == b'\n':
        continue



p = GCD(pow(sig, e, n) - c, n)
q = n//p
assert p*q == n

d = inverse(e, (p-1)*(q-1))

print(long_to_bytes(pow(ct, d, n)))




io.interactive()