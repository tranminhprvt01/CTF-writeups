from pwn import *

io = remote("pwn.friendly.securinets.tn", "5003")


io.sendlineafter(b'It better be a password no one can type with their keyboard\n', b"\xc8\x65\xff\x16\x42\xf7")


io.interactive()