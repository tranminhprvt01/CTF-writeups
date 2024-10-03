from pwn import *

io = remote("reversecryptographing.nc.jctf.pro", 1337)


# determine padding len
io.sendline(b'')
ct = bytes.fromhex(io.recvline().rstrip().decode())

print(ct.hex())

for i in range(1, 16):
    io.sendline(f"{((i.to_bytes(1, 'big'))*(i)).hex()}")
    recv = bytes.fromhex(io.recvline().rstrip().decode())
    if recv == ct:
        print("Found with", i, "padding")
        pad_len = i
        break


known_suf = b'justCTF{y4d_yyyyPP4h_r333bMer_yAwl4__krr4d_5i_yaD_n3w}'

#we know if input the suffix the padding will increase -> which make us find the  previous suffix
while True:
    if known_suf.startswith(b'justCTF{'):
        break
    io.sendline(known_suf[::-1].hex())
    ct = bytes.fromhex(io.recvline().rstrip().decode())

    print(ct.hex())

    #brute force the next suffix match
    for i in range(32, 127):
        io.sendline(f"{known_suf[::-1].hex() + ((i.to_bytes(1, 'big'))*2).hex()}")
        recv = bytes.fromhex(io.recvline().rstrip().decode())
        if recv == ct:
            print("Found suffix", i)
            known_suf = bytes([i]) + known_suf
            break

    print(known_suf)




io.interactive()

