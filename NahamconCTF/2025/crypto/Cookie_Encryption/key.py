from Crypto.PublicKey import RSA

# Tạo cặp khóa RSA
key = RSA.generate(1024)

# Lưu private key vào file new_private_key.pem
with open("new_private_key.pem", "wb") as f:
    f.write(key.export_key())

# Lưu public key vào file new_public_key.pem
with open("new_public_key.pem", "wb") as f:
    f.write(key.publickey().export_key())

print("Đã tạo thành công new_private_key.pem và new_public_key.pem")