#nc 2024.ductf.dev 30020
#!/usr/bin/env python3

from Crypto.Cipher import AES
import os

KEY = os.urandom(16)
IV = os.urandom(16)
FLAG = os.getenv('FLAG', 'DUCTF{testflag}')

def main():
    while True:
        ct = bytes.fromhex(input('ct: '))
        aes = AES.new(KEY, AES.MODE_CFB, IV, segment_size=128)
        try:
            #print(aes.decrypt(ct))
            print(eval(aes.decrypt(ct)))
        except Exception as e:
            print('invalid ct!', e)

if __name__ == '__main__':
    main()
