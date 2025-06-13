from pwn import *
from Crypto.Cipher import AES
import egcd
from Crypto.Util.number import *

io = remote('choose.chal.cyberjousting.com', 1348)


io.recvuntil(b'[+] Generating values...\n')
ct = bytes.fromhex(io.recvline().rstrip().decode())


io.recvuntil(b'We will encrypt the key three times, and you can even choose the value of e. Please put your distinct e values in increasing order.\n')
io.sendline(b'2 3 5')


io.recvuntil(b'n0=')
n0 = int(io.recvline().rstrip().decode())
io.recvuntil(b'c0=')
c0 = int(io.recvline().rstrip().decode())

io.recvuntil(b'n1=')
n1 = int(io.recvline().rstrip().decode())
io.recvuntil(b'c1=')
c1 = int(io.recvline().rstrip().decode())

io.recvuntil(b'n2=')
n2 = int(io.recvline().rstrip().decode())
io.recvuntil(b'c2=')
c2 = int(io.recvline().rstrip().decode())





print(GCD(n0, n1))
print(GCD(n0, n2))
print(GCD(n1, n2))







io.interactive()