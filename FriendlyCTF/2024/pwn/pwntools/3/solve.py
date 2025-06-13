from pwn import *

io = remote("pwn.friendly.securinets.tn", "5004")

nums = []

for i in range(0x10):
    nums.append(io.recvline().rstrip().decode())

for i in range(0x10):
    io.sendline(nums[i])

io.interactive()