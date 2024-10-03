from pwn import *

from mt19937predictor import MT19937Predictor #https://github.com/kmyk/mersenne-twister-predictor



#target = process(["python3", "casino.py"])

target = remote("chal-kalmarc.tf", 9)

target.recvline()

target.recvline()

q = int(target.recvline().decode()[3:])

g = int(target.recvline().decode()[3:])

h = int(target.recvline().decode()[3:])



predictor = MT19937Predictor()



target.recvuntil(b"[C]ards")

target.send(b"N\n")



guess = 0

game = 0

for _ in range(1337):

    comm = int(target.recvline().decode()[len("Commitment:"):])

    if guess < 625:

        guess += 1

        target.sendlineafter(b"[Y]es/[N]o", b"N")

        v = int(target.recvline().decode()[len("commited value was "):])

        r = int(target.recvline().decode()[len("randomness used was "):])

        target.recvline()

        predictor.setrandbits(v, 32)

    else:

        target.sendlineafter(b"[Y]es/[N]o", b"Y")

        target.sendlineafter(b"whats your guess?", (str(predictor.randint(0, 2**32-2))).encode())

        target.recvline()

        game += 1

    if game == 100:

        target.interactive()
