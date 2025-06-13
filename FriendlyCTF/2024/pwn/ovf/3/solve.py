from pwn import *

io = remote("pwn.friendly.securinets.tn", "5008")


io.interactive()