from pwn import *

io = process(["python3", "chall.py"])


io.interactive()