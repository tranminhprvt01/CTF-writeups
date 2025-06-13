
from pwn import *
import time


io = process(["python", "decrypt-then-eval.py"])
#io = remote("2024.ductf.dev", 30020)

cmd = b'FLAG'
res = b''
target = b'1234'
for index in range(len(cmd)):
    for char in range(256):
        io.sendlineafter(b'ct: ', (res+bytes([char])).hex())
        if io.recvline()[index] == target[index]:
            res+=bytes([char])
            time.sleep(10)
            break
        else: continue


print(res, len(res))

io.sendlineafter(b'ct: ', (xor(cmd, res, target)).hex())

io.interactive()

#DUCTF{should_have_used_authenticated_encryption!}




