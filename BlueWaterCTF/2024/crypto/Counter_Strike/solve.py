from Crypto.Cipher import AES
from os import urandom


key, nonce = urandom(16), urandom(12)
print(key.hex())
print(nonce.hex())


while cmd := input("> "):
	if cmd == "reset":
		cipher = AES.new(key, AES.MODE_GCM, nonce)
		pt, ct, tag = None, None, None

	elif cmd == "encrypt":
		pt = urandom(256 + urandom(1)[0])
		print(cipher._key.hex())
		print(cipher.nonce.hex())
		#print(cipher.counter.hex())
		ct = cipher.encrypt(pt)
		print(f"pt: {pt.hex()} {len(pt)}")

	elif cmd == "tag":
		tag = cipher.digest()
		if pt: print(f"tag: {tag.hex()}")

	elif cmd == "verify":
		tag = cipher.digest()
		if (input("ct: "), input("tag: ")) == (ct.hex(), tag.hex()):
			print(flag)
