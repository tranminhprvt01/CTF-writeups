from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long, long_to_bytes
from pwn import process, context
import logging
import sys
from random import randrange

# Thiết lập logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)

# Thiết lập context cho pwntools
context.log_level = 'info'

# Hàm hỗ trợ cho Bleichenbacher
def floor_div(a, b):
    return a // b

def ceil_div(a, b):
    return a // b + (a % b > 0)

def _insert(M, a, b):
    print("in")
    for i, (a_, b_) in enumerate(M):
        if a_ <= b and a <= b_:
            a = min(a, a_)
            b = max(b, b_)
            M[i] = (a, b)
            return
    print("lmao")
    M.append((a, b))
    #return

# Step 1
def _step_1(padding_oracle, n, e, c):
    s0 = 1
    c0 = c
    while not padding_oracle(c0):
        s0 = randrange(2, n)
        c0 = (c * pow(s0, e, n)) % n
    return s0, c0

# Step 2.a
def _step_2a(padding_oracle, n, e, c0, B):
    s = ceil_div(n, 3 * B)
    while not padding_oracle((c0 * pow(s, e, n)) % n):
        s += 1
        print(s)
    return s

# Step 2.b
def _step_2b(padding_oracle, n, e, c0, s):
    s += 1
    while not padding_oracle((c0 * pow(s, e, n)) % n):
        s += 1
    return s

# Step 2.c
def _step_2c(padding_oracle, n, e, c0, B, s, a, b):
    r = ceil_div(2 * (b * s - 2 * B), n)
    while True:
        left = ceil_div(2 * B + r * n, b)
        right = floor_div(3 * B + r * n, a)
        for s in range(left, right + 1):
            if padding_oracle((c0 * pow(s, e, n)) % n):
                return s
        r += 1

# Step 3
def _step_3(n, B, s, M):
    print(n, B, s, M)
    M_ = []
    for (a, b) in M:
        left = ceil_div(a * s - 3 * B + 1, n)
        right = floor_div(b * s - 2 * B, n)
        print(left, right)
        for r in range(left, right + 1):
            a_ = max(a, ceil_div(2 * B + r * n, s))
            b_ = min(b, floor_div(3 * B - 1 + r * n, s))
            _insert(M_, a_, b_)
    return M_

# Hàm tấn công Bleichenbacher
def attack(padding_oracle, n, e, c):
    k = ceil_div(n.bit_length(), 8)
    B = 2 ** (8 * (k - 2))
    logging.info("Executing step 1...")
    s0, c0 = _step_1(padding_oracle, n, e, c)
    print(s0, c0)
    M = [(2 * B, 3 * B - 1)]
    logging.info("Executing step 2.a...")
    s = _step_2a(padding_oracle, n, e, c0, B)
    print(s)
    print(M)
    M = _step_3(n, B, s, M)
    print(M)
    logging.info("Starting while loop...")
    while True:
        print(M)
        if len(M) > 1:
            s = _step_2b(padding_oracle, n, e, c0, s)
        else:
            (a, b) = M[0]
            if a == b:
                m = (a * pow(s0, -1, n)) % n
                return m
            s = _step_2c(padding_oracle, n, e, c0, B, s, a, b)
        M = _step_3(n, B, s, M)

def register(username, password):
    io.recvuntil(b'>>')
    io.sendline(b'1')  # Chọn đăng nhập
    io.recvuntil(b'user>')
    io.sendline(username.encode())
    io.recvuntil(b'pass>')
    io.sendline(password.encode())
    io.recvuntil(b'confirm>')
    io.sendline(password.encode())




# Tương tác với demo.py bằng pwntools
def login(username, password):
    io.recvuntil(b'>>')
    io.sendline(b'2')  # Chọn đăng nhập
    io.recvuntil(b'user>')
    io.sendline(username.encode())
    io.recvuntil(b'pass>')
    io.sendline(password.encode())
    output = io.recvuntil(b'=== Menu ===').decode()
    
    if "Đăng nhập thành công!" in output:
        # Lấy cookie từ output
        for line in output.split('\n'):
            if line.startswith('Cookie:'):
                cookie = line.split('Cookie: ')[1].strip()
                print(f"Đăng nhập thành công cho {username}, Cookie: {cookie}")
                return cookie
    print("Đăng nhập thất bại!")
    return None

def check_cookie(c):
    io.recvuntil(b'>>')
    io.sendline(b'3')  # Chọn kiểm tra cookie
    io.recvuntil(b'cookie(hex)>')
    io.sendline(c.encode())
    output = io.recvuntil(b'=== Menu ===').decode()
    
    if "The secret is all good!" in output:
        #print(f"Cookie {c}: The secret is all good!")
        return True
    #print(f"Cookie {c}: The secret is not all good!")
    return False

def padding_oracle(value):
    cookie_hex = long_to_bytes(value).hex()
    return check_cookie(cookie_hex)



# Lấy khóa công khai
pub = RSA.import_key(open('new_public_key.pem', 'r').read())
n = pub.n
e = pub.e

# Khởi tạo process duy nhất
io = process(['python', 'demo.py'])



register('a', '123')


# Đăng nhập để lấy cookie
cookie = login('admin', 'admin')

if not cookie:
    print("Không thể lấy cookie!")
    io.close()




# Chuyển cookie thành số nguyên
c = bytes_to_long(bytes.fromhex(cookie))


print(c)

# Chạy tấn công Bleichenbacher
plaintext = attack(padding_oracle, n, e, c)
print("Plaintext (integer):", plaintext)
print("Plaintext (bytes):", long_to_bytes(plaintext))

# Đóng process
p.close()
