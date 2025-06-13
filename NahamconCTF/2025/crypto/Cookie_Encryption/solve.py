from Crypto.Util.number import bytes_to_long, long_to_bytes
import requests
from Crypto.PublicKey import RSA
import logging
import sys
from random import randrange

# Thiết lập logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)

# Hàm hỗ trợ cho Bleichenbacher
def floor_div(a, b):
    return a // b

def ceil_div(a, b):
    return a // b + (a % b > 0)

def _insert(M, a, b):
    for i, (a_, b_) in enumerate(M):
        if a_ <= b and a <= b_:
            a = min(a, a_)
            b = max(b, b_)
            M[i] = (a, b)
            return
    M.append((a, b))

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
    M_ = []
    for (a, b) in M:
        left = ceil_div(a * s - 3 * B + 1, n)
        right = floor_div(b * s - 2 * B, n)
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
    M = [(2 * B, 3 * B - 1)]
    logging.info("Executing step 2.a...")
    s = _step_2a(padding_oracle, n, e, c0, B)
    print(s)
    M = _step_3(n, B, s, M)
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

# Lấy khóa công khai
pub = RSA.import_key(open('public_key.pem', 'r').read())
n = pub.n
e = pub.e

# Định nghĩa URL cơ sở của server
base_url = 'http://challenge.nahamcon.com:31130'

def login(username, password):
    session = requests.Session()  # Tạo session mới
    login_url = f"{base_url}/login"
    data = {'username': username, 'password': password}
    response = session.post(login_url, data=data)
    
    if response.status_code == 200 and 'secret' in session.cookies:
        print(f"Đăng nhập thành công cho {username}")
        print(f"Cookie secret ban đầu: {session.cookies['secret']}")
        print(f"Cookies sau đăng nhập: {session.cookies.get_dict()}")
        return session.cookies['secret'], session
    else:
        print(f"Đăng nhập thất bại: {response.text}")
        print(f"Response status: {response.status_code}")
        print(f"Response cookies: {response.cookies.get_dict()}")
        return None, None

def check_cookie(c, session):
    # Chỉ đặt cookie secret, giữ cookie session
    cookies = {'secret': c.hex()}
    if 'session' in session.cookies:
        cookies['session'] = session.cookies['session']
    url = f'{base_url}/cookie'
    r = session.get(url, cookies=cookies)
    content = r.content.decode().strip()
    print(f"Check cookie response: {content}")
    return content == "The secret is all good!"

def padding_oracle(session):
    def oracle(value):
        return check_cookie(long_to_bytes(value), session)
    return oracle

# Hàm chính
def main():
    # Đăng nhập với admin để kiểm tra
    cookie_admin, session_admin = login('admin', 'admin')
    if cookie_admin:
        print("Cookie admin:", cookie_admin)

    # Đăng nhập với user thường
    #cookie_a, session_a = login('a', '12345')
    #if not cookie_a:
    #    print("Không thể lấy cookie!")
    #    return
    
    #print("Cookie a:", cookie_a)
    c = bytes_to_long(bytes.fromhex(cookie_admin))

    # Chạy tấn công Bleichenbacher
    plaintext = attack(padding_oracle(session_admin), n, e, c)
    print("Plaintext (integer):", plaintext)
    try:
        print("Plaintext (bytes):", long_to_bytes(plaintext).decode())
    except UnicodeDecodeError:
        print("Plaintext (bytes): Cannot decode to string, raw bytes:", long_to_bytes(plaintext).hex())

if __name__ == "__main__":
    main()