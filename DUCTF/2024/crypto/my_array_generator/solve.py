from pwn import *

io = process(["python", "challenge.py"])

io.interactive()