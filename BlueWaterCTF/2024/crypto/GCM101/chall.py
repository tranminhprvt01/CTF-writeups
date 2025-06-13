from Crypto.Cipher import AES
from random import randint
from os import urandom
FLAG = b'BKISC{sample_flag}'

    
def decrypt_gcm(key, iv, ct, tag, aad=None):
    try:
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        if aad:
            cipher.update(aad)
        pt = cipher.decrypt_and_verify(ct, tag)
        return pt
    except ValueError as e:
        print(f"Decryption failed: {e}")
        return None


#main 
def main():
    print("AES-GCM 101:")
    tag = urandom(16)
    tag = tag.hex()
    aad = urandom(16)
    aad = aad.hex()
    need_message = urandom(1000)
    sendout_message = need_message.hex()
    print("tag: ", tag)
    print("aad: ", aad)
    print("need_message: ", sendout_message)
    print("Provide the key and ciphertext to get the flag")
    key = input("key> ")
    ciphertext = input("ciphertext> ")
    key = bytes.fromhex(key)
    ciphertext = bytes.fromhex(ciphertext)
    
    answer = decrypt_gcm(key,ciphertext[:12],ciphertext[12:-16],ciphertext[-16:])
    if answer == None:
        # print("Decryption failed")
        exit(0)
    elif need_message in answer:
        print("Congrats! Here is the flag:")
        print(FLAG)
    
    
main()