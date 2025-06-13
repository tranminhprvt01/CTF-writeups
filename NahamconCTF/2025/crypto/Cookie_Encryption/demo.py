from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5

# Khởi tạo dictionary lưu trữ người dùng
users = {
    'admin': 'admin'  # username: password
}

# Hàm mã hóa/giải mã
private_key = RSA.importKey(open('new_private_key.pem').read())
public_key = private_key.publickey()

def encrypt(plaintext):
    cipher_rsa = PKCS1_v1_5.new(public_key)
    ciphertext = cipher_rsa.encrypt(plaintext)
    return ciphertext

def decrypt(ciphertext):
    sentinel = b"Error in decryption!"
    try:
        cipher_rsa = PKCS1_v1_5.new(private_key)
        plaintext = cipher_rsa.decrypt(ciphertext, sentinel)
        if plaintext != b'':
            return plaintext
        else:
            raise ValueError
    except:
        return sentinel

# Mô phỏng trạng thái đăng nhập
current_user = None
current_secret = None

# Hàm kiểm tra trạng thái đăng nhập
def is_authed():
    return current_user is not None

# Hàm đăng nhập
def login():
    global current_user, current_secret
    print("\n--- Đăng nhập ---")
    username = input("user>").strip()
    password = input("pass>").strip()
    
    if username in users:
        if users[username] == password:
            current_user = {'username': username}
            if username == "admin":
                current_secret = encrypt(b"flag{this_is_not_the_hell}").hex()  # Thay FLAG bằng giá trị thực
                print("Cookie:", current_secret)
            else:
                current_secret = encrypt(b"This is not the admin secret!").hex()
                print("Cookie:", current_secret)
            print("Đăng nhập thành công!")
        else:
            print("Mật khẩu không đúng!")
    else:
        print("Không tìm thấy người dùng với tên này!")

# Hàm đăng ký
def register():
    global current_user, current_secret
    print("\n--- Đăng ký ---")
    username = input("user>").strip()
    password = input("pass>").strip()
    confirm = input("confirm>").strip()
    
    errors = []
    if password != confirm:
        errors.append("Mật khẩu xác nhận không khớp!")
    if len(password) < 3:
        errors.append("Mật khẩu phải dài hơn 3 ký tự!")
    if username in users:
        errors.append("Tên người dùng đã tồn tại!")
    
    if errors:
        for error in errors:
            print(error)
        return
    
    users[username] = password
    current_user = {'username': username}
    current_secret = encrypt(b"This is not the admin secret!").hex()
    print("Đăng ký thành công!")

# Hàm kiểm tra secret
def check_cookie():
    if not is_authed():
        print("Vui lòng đăng nhập trước!")
        return
    
    print("\n--- Kiểm tra cookie ---")
    custom_cookie = input("cookie(hex)>").strip()

    secret = decrypt(bytearray.fromhex(custom_cookie))
    if b"Error" not in secret:
        print("The secret is all good!")
    else:
        print("The secret is not all good!")

# Giao diện dòng lệnh
def main():
    while True:
        print("\n=== Menu ===")
        print("1. Đăng ký")
        print("2. Đăng nhập")
        print("3. Kiểm tra cookie")
        print("4. Thoát")
        choice = input(">> ")
        
        if choice == '1':
            register()
        elif choice == '2':
            login()
        elif choice == '3':
            check_cookie()
        elif choice == '4':
            print("Tạm biệt!")
            break
        else:
            print("Lựa chọn không hợp lệ!")

if __name__ == "__main__":
    main()