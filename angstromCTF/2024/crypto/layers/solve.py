from pwn import *
import string




enc_flag = 'fb7fdbf9e714a08ce9cdf109bb527acba27accfeff16fcdcb1cdf358bb557898aa2d9da9af5c'


flag = 'actf{'
tmp = ''
alphabet = string.digits + "{_}" + string.ascii_letters
print(alphabet)
while True:
    for char in alphabet:
        tmp=flag + char
        io = remote("challs.actf.co", 31398)
        io.sendlineafter(b'Pick 1, 2, or 3 >', b'1')
        io.sendlineafter(b'Your message > ', tmp.encode())
        res = io.recvline().rstrip().decode()
        if res == enc_flag[:len(res)]:
            flag+=char
            print(flag)
            print(res)
            break

io.interactive()