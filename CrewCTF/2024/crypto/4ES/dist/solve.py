from hashlib import sha256
from random import choices

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


import itertools




"""
check = False
cnt = 0

for w in itertools.combinations_with_replacement(chars, 3):
    if check: break
    for x in itertools.combinations_with_replacement(chars, 3):
        if check: break
        for y in itertools.combinations_with_replacement(chars, 3):
            if check: break
            for z in itertools.combinations_with_replacement(chars, 3):
                if check: break
                w_ = bytes(w)
                x_ = bytes(x)
                y_ = bytes(y)
                z_ = bytes(z)

                k1 = sha256(w_).digest()
                k2 = sha256(x_).digest()
                k3 = sha256(y_).digest()
                k4 = sha256(z_).digest()

                ct = AES.new(k4, AES.MODE_ECB).encrypt(
                        AES.new(k3, AES.MODE_ECB).encrypt(
                            AES.new(k2, AES.MODE_ECB).encrypt(
                                AES.new(k1, AES.MODE_ECB).encrypt(
                                    pt
                                )
                            )
                        )
                    )
                cnt+=1
                if ct == bytes.fromhex('edb43249be0d7a4620b9b876315eb430'):
                    print("FOUND")
                    print(w_)
                    print(x_)
                    print(y_)
                    print(z_)
                    key = sha256(w + x + y + z).digest()
                    flag = AES.new(key, AES.MODE_ECB).decrypt(bytes.fromhex(enc_flag))
                    print(flag)
                    check = True
                    break
                if cnt % 1000000000 == 0:
                    print(cnt)
                    print(w_)
                    print(x_)
                    print(y_)
                    print(z_)
"""




pt = bytes.fromhex('4145535f4145535f4145535f41455321')
ct = bytes.fromhex('edb43249be0d7a4620b9b876315eb430')

print(pt)

enc_flag = bytes.fromhex('e5218894e05e14eb7cc27dc2aeed10245bfa4426489125a55e82a3d81a15d18afd152d6c51a7024f05e15e1527afa84b')

chars = b'crew_AES*4=$!?'




cnt = 0

ls = []

for i in itertools.product(chars, repeat=3):
    ls.append(bytes(i))


print(len(ls))

print(ls[:10])

cnt = 0 
check = False
while True:
    if check: break
    print(f"Attempt {cnt}")
    tmp = choices(ls, k=len(ls)**2)
    print(len(tmp))
    print(tmp[:10])
    for i in range(0, len(tmp), 4):
        x = b''.join(tmp[i:i+4])
        #print(x)
        key = sha256(x).digest()
        aes = AES.new(key, AES.MODE_ECB)
        res = aes.decrypt(enc_flag)
        if res.startswith(b'crew{'):
            print("FOUND")
            print(x)
            print(res)
            check = True
            break
    cnt+=1
    
