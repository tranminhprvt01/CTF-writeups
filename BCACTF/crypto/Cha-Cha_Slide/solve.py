from pwn import *

io = remote("challs.bcactf.com", 31594)

io.recvuntil(b'Secret message:\n')
enc_sec = bytes.fromhex(io.recvline().rstrip().decode())

payload = b'\x00'*16
io.sendlineafter(b'\nEnter your message:\n', payload.hex())

io.recvuntil(b'\nEncrypted:\n')
enc_m = bytes.fromhex(io.recvline().rstrip().decode())

sec = xor(xor(enc_m, payload.hex().encode()), enc_sec)
print(sec, "recover")
io.sendlineafter(b'\nEnter decrypted secret message:\n', sec.decode())

io.interactive()