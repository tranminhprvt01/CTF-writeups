"""
+ TARGET: DATE 34 times and get flag <- require 2^34 intelligence w
+ client encrypt data using aes_gcm with this info

        def encrypt_data(ID, PW, character):
            id_hash = hashlib.sha256(ID.encode()).digest()
            pw_hash = hashlib.sha256(PW.encode()).digest()
            nonce = id_hash[:12]
            file_name = id_hash[16:24].hex()
            key = pw_hash[:16]
            cipher = AES.new(key, AES.MODE_GCM, nonce)

            file_data = b''
            file_data += len(character.nickname).to_bytes(2, 'little')
            file_data += character.nickname.encode()
            file_data += character.day.to_bytes(4, 'little')
            file_data += character.stamina.to_bytes(4, 'little')
            file_data += character.intelligence.to_bytes(4, 'little')
            file_data += character.friendship.to_bytes(4, 'little')

            file_data = pad(file_data, 16)
            file_data_enc, tag = cipher.encrypt_and_digest(file_data)
            return file_data_enc, tag

"""


import json
from pwn import *
import hashlib
from Crypto.Util.Padding import pad
from Crypto.Cipher import AES


class Character:
    def __init__(self, nickname='', day=0, stamina=0, intelligence=0, friendship=0):
        self.nickname = nickname
        self.day = day
        self.stamina = stamina
        self.intelligence = intelligence
        self.friendship = friendship
    





EAT_COMMAND = 1
PWN_COMMAND = 2
SLEEP_COMMAND = 3
DATE_COMMAND = 4
SAVE_COMMAND = 5

SAVE_SUCCESS = 11
SAVE_FAIL = 12


def id_pw_validity_check(ID, PW):
    if len(ID) < 20 or len(PW) < 20:
        return False
    if len(set(ID)) < 20 or len(set(PW)) < 20:
        return False
    if ID == PW:
        return False
    return True


def encrypt_data(ID, PW, character):
    id_hash = hashlib.sha256(ID.encode()).digest()
    pw_hash = hashlib.sha256(PW.encode()).digest()
    nonce = id_hash[:12]
    file_name = id_hash[16:24].hex()
    key = pw_hash[:16]
    cipher = AES.new(key, AES.MODE_GCM, nonce)

    file_data = b''
    file_data += len(character.nickname).to_bytes(2, 'little')
    file_data += character.nickname.encode()
    file_data += character.day.to_bytes(4, 'little')
    file_data += character.stamina.to_bytes(4, 'little')
    file_data += character.intelligence.to_bytes(4, 'little')
    file_data += character.friendship.to_bytes(4, 'little')

    file_data = pad(file_data, 16)
    file_data_enc, tag = cipher.encrypt_and_digest(file_data)
    return file_data_enc, tag


with open("credential", 'r') as f:
    info = json.loads(f.read())
    ID = info["ID"]
    PW = info["PW"]
    nickname = info["nickname"]


print(ID)
print(PW)
print(nickname)
assert id_pw_validity_check(ID, PW)

io = remote("localhost", 12345)

io.send(len(ID).to_bytes(2, 'little') + ID.encode())
io.send(len(PW).to_bytes(2, 'little') + PW.encode())

status = io.recv(1)
character = Character('You', 0, 100, 0, 0)

if status == b'\x02':
    #load failed
    io.send(len(nickname).to_bytes(2, 'little') + nickname.encode())


    """
    #Gain intelligence by pwning
    io.send(PWN_COMMAND.to_bytes(1, 'little'))
    rnd = int.from_bytes(io.recv(1), 'little')
    if rnd == 0:
        print("SERVER CLOSE CONNETION")
    """


    #save game
    io.send(SAVE_COMMAND.to_bytes(1, 'little'))
    file_data_enc, tag = encrypt_data(ID, PW, character)



    print(file_data_enc)
    print(tag)


    io.send(len(file_data_enc).to_bytes(2, 'little') + file_data_enc)
    io.send(tag)



    io.interactive()

elif status == b'\x01':
    nickname_len = int.from_bytes(io.recv(2), 'little')
    nickname_ = io.recv(nickname_len).decode()
    day_ = int.from_bytes(io.recv(4), 'little')
    stamina_ = int.from_bytes(io.recv(4), 'little')
    intelligence_ = int.from_bytes(io.recv(4), 'little')
    friendship_ = int.from_bytes(io.recv(4), 'little')