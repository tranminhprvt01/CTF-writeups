from pwn import *
import json

io = process(["python", "challenge.py"])

io.interactive()