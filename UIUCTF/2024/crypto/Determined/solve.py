from pwn import *

io = remote("determined.chal.uiuc.tf", 1337, ssl=True)

io.interactive()