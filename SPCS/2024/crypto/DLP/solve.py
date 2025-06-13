#nc ctf.mf.grsu.by 9030

from pwn import *
from sympy.ntheory import discrete_log
from Crypto.Util.number import *

io = remote("ctf.mf.grsu.by", 9030)


io.sendlineafter(b'Your choice: ', b'1')

p = int(io.recvline().rstrip().decode()[3:])
g = int(io.recvline().rstrip().decode()[3:])
h = int(io.recvline().rstrip().decode()[3:])


x = discrete_log(p, h, g)

print(x)


io.sendlineafter(b'Your choice: ', b'2')
io.sendlineafter(b'Your answer: ', long_to_bytes(x))


io.interactive()