from pwn import *


io = process(["python", "hashbrown.py"])


io.interactive()