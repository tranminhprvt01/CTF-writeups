from pwn import *
import string

#io = remote("localhost", 1337)
while True:
    io = remote("pad.ctf.intigriti.io", 1348)


    io.recvuntil(b"Encrypted (cat state=ERROR! 'cat not in box'): ")
    enc_flag = bytes.fromhex(io.recvline().rstrip().decode())

    payload = b'\x00'*160
    io.sendlineafter(b"Anyway, why don't you try it for yourself?\n", payload)

    io.recvuntil(b"Encrypted (cat state=")
    state = 1 if io.recvuntil(b'): ')[:-3].rstrip().decode() == 'alive' else 0
    print(state)
    ct = bytes.fromhex(io.recvline().rstrip().decode())
    ls = list(ct)
    print(ls)

    if state == 1:
        ls = [i^0xAC for i in ls]
        ls = [(i >> 1) for i in ls]
        print(bytes(ls))
        key = bytes(ls)
        assert all(i in string.ascii_letters + string.digits for i in key.decode())
        break
    else:
        print("Retry")
        io.close()




flag = xor(key, enc_flag)

print(flag)




io.interactive()