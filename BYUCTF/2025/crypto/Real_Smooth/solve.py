from pwn import *


io = remote('smooth.chal.cyberjousting.com', 1350)


known = b'Slide to the leftSlide to the right'
ct = bytes.fromhex((io.recvline().rstrip() + io.recvline().rstrip()).decode())

print(ct)

assert len(known) == len(ct)


target = b'Criss cross, criss cross'
sent = xor(xor(known, ct)[:len(target)], target)

io.sendline(sent.hex())



io.interactive()