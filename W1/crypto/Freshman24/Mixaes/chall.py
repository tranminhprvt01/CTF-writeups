#nc 20.255.51.113 1503
from Crypto.Util.number import *
import os
from Crypto.Cipher import AES

FLAG = open('flag.txt', 'r').read()

class My_Cipher:
    def __init__(self, key):
        self.key = key

    def xor(self, a, b):
        return bytes([x ^ y for x, y in zip(a, b)])

    def encrypt(self, plaintext):
        IV = os.urandom(16)
        state = b"\x00" * 16
        cipher = AES.new(self.key, AES.MODE_ECB)
        ct = b""
        for i in range(0, len(plaintext), 16):
            state = cipher.encrypt(self.xor(state, plaintext[i:i + 16]))
            ct += self.xor(state, IV)
            state = ct[i:i + 16]
        return IV + ct

    def decrypt(self, ciphertext):
        IV = ciphertext[:16]
        ct = ciphertext[16:]
        cipher = AES.new(self.key, AES.MODE_ECB)
        pt = b''
        state = b"\x00" * 16
        for i in range(0, len(ct), 16):
            pt += self.xor(state, cipher.decrypt(self.xor(IV, ct[i:i + 16])))
            state = ct[i:i + 16]
        return pt
    
# Challenge
class Challenge():
    def __init__(self):
        self.key = os.urandom(16)
        self.cipher = My_Cipher(self.key)
        self.password = b"This is my real password!!!!!!!!" + os.urandom(16)
        self.password_length = len(self.password)

    def reset_password(self, option):
        if option == "Y":
            self.password = b"This is my real password!!!!!!!!" + os.urandom(16)
            return "Complete!"
        elif option == "N":
            self.password =  self.password[16:] + os.urandom(16)
            return "Complete!"
        return "Cheating???"
    
    def create_password(self, token):
        if len(token) < 28 or len(token) % 16 != 0:
            print("Cheating???")
            return
        token = self.cipher.decrypt(token)
        self.password_length = bytes_to_long(token[-4:])
        self.password = token[:self.password_length]

    def show_enc_password(self):
        return self.cipher.encrypt(self.password)
    
    def check_password(self, password):
        if self.password == password:
            return True
        return False

print('''
      You have to break password to get the FLAG
''')

chall = Challenge()

menu = '''
1) Show encrypted password
2) Reset password
3) Create new password
4) Guess the password
> '''

while True:
    print(menu, end='')
    # print("> ")
    opt = input().strip()
    if opt == '1':
        print("enc (hex):", chall.show_enc_password().hex())
    elif opt == '2':
        print('Do you want to reset full password? ([Y]/[N])\n> ', end='')
        check = input().strip()
        print(chall.reset_password(check))
    elif opt == '3':
        token = bytes.fromhex(input("token (hex): ").strip())
        chall.create_password(token)
    elif opt == '4':
        password = bytes.fromhex(input("password (hex): ").strip())
        if chall.check_password(password):
            print(FLAG)
            exit(0)
        print("Wrong!!!!!!")
    else:
        print("Cheating????")

