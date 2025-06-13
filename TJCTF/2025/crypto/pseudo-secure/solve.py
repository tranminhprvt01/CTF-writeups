#!/usr/bin/env python3
from pwn import *
import base64
from math import ceil
from randcrack import RandCrack

# (Các hàm helper không thay đổi)
def reverse_key(key, username):
    try:
        num_bits = len(username) * 8; username_int = int(''.join(bin(ord(c))[2:].zfill(8) for c in username), 2)
        key_padded = key + '='*(-len(key)%4); byte_data = base64.b64decode(key_padded); shifted = int.from_bytes(byte_data, 'big')
    except Exception: return None
    temp = shifted ^ 0x5A
    if temp % 8 != 0: return None
    xor_result = temp >> 3
    if xor_result.bit_length() > num_bits: return None
    rand = xor_result ^ username_int
    if rand.bit_length() > num_bits: return None
    return rand

def generate_key_from_rand(rand, username):
    num_bits = 8 * len(username); rand_bits = bin(rand)[2:].zfill(num_bits); username_bits = ''.join([bin(ord(char))[2:].zfill(8) for char in username])
    xor_result = int(''.join([str(int(a)^int(b)) for a,b in zip(rand_bits,username_bits)]), 2)
    shifted = ((xor_result << 3) & ((1 << (num_bits + 3)) - 1)) ^ 0x5A
    byte_data = shifted.to_bytes((shifted.bit_length() + 7) // 8, 'big'); key = base64.b64encode(byte_data).decode('utf-8')
    return key

# --- Giai đoạn 1: Thu thập và Bẻ khóa (Không thay đổi) ---
context.log_level = 'info'
HOST = 'tjc.tf'; PORT = 31400
cracker = RandCrack()
log.info("--- Giai đoạn 1: Bắt đầu thu thập dữ liệu ---")
s_collect = remote(HOST, PORT)
USER_LEN = 128; WORDS_PER_USER = ceil(USER_LEN*8/32); SAMPLES_NEEDED = 624
USERS_TO_CREATE = ceil(SAMPLES_NEEDED / WORDS_PER_USER); samples_collected = 0
for i in range(USERS_TO_CREATE):
    if samples_collected >= SAMPLES_NEEDED: break
    username = (f"u{i:02}"*(USER_LEN//3))[:USER_LEN]
    s_collect.sendlineafter(b'[Q] Quit', b'2'); s_collect.sendlineafter(b'Select username:  ', username.encode())
    s_collect.recvuntil(b'Your sign-in key is: '); key = s_collect.recvline().strip().decode()
    rand_val = reverse_key(key, username)
    if rand_val is None: log.error(f"Không thể đảo ngược key. Dừng lại."); s_collect.close(); exit(1)
    for j in range(WORDS_PER_USER):
        if samples_collected >= SAMPLES_NEEDED: break
        word = (rand_val >> (j*32)) & 0xFFFFFFFF; cracker.submit(word); samples_collected += 1
    log.info(f"User #{i+1}: Đã nạp {samples_collected}/{SAMPLES_NEEDED} words.")
s_collect.close()
log.success("--- Giai đoạn 1 Hoàn thành: RNG đã được bẻ khóa. ---")

# --- Giai đoạn 2: Khai thác với Brute-force Offset ---
log.info("--- Giai đoạn 2: Thử các offset để tìm đúng key ---")
admin_users = ["Admin001", "Admin002", "Admin003"]

for offset in range(10): # Thử bỏ qua từ 0 đến 9 số 64-bit đầu tiên
    log.info(f"[*] Thử với offset = {offset}...")
    
    # Tạo một bản sao của cracker để không làm hỏng bản gốc
    temp_cracker = cracker.clone()
    temp_cracker.index = 0
    
    try:
        # Bỏ qua 'offset' số ngẫu nhiên
        for _ in range(offset):
            temp_cracker.predict_getrandbits(64)
            
        # Dự đoán key cho admin với offset hiện tại
        admin_keys = []
        for user in admin_users:
            rand64 = temp_cracker.predict_getrandbits(64)
            key = generate_key_from_rand(rand64, user)
            admin_keys.append(key)

        # Thử đăng nhập với key của Admin001
        s_exploit = remote(HOST, PORT)
        s_exploit.sendlineafter(b'[Q] Quit', b'1')
        s_exploit.sendlineafter(b'Enter your username:  ', b'Admin001')
        s_exploit.sendlineafter(b'Enter your sign-in key: ', admin_keys[0].encode())
        
        # Kiểm tra phản hồi
        response = s_exploit.recvline()
        if b'Welcome,' in response:
            log.success(f"[+] Tìm thấy offset chính xác: {offset}!")
            log.success(f"Key đúng cho Admin001: {admin_keys[0]}")

            # Đã đăng nhập thành công, giờ lấy nốt flag
            flag_parts = []
            
            # Lấy phần 1
            s_exploit.sendlineafter(b'[L] Logout', b'1'); s_exploit.recvuntil(b'Your message: ')
            flag_part1 = s_exploit.recvline().strip().decode(); flag_parts.append(flag_part1)
            s_exploit.sendlineafter(b'[L] Logout', b'l')
            log.success(f"Lấy được phần 1: {flag_part1}")

            # Lấy phần 2
            s_exploit.sendlineafter(b'[Q] Quit', b'1'); s_exploit.sendlineafter(b'username:  ', b'Admin002')
            s_exploit.sendlineafter(b'key: ', admin_keys[1].encode()); s_exploit.recvuntil(b'Welcome,')
            s_exploit.sendlineafter(b'[L] Logout', b'1'); s_exploit.recvuntil(b'Your message: ')
            flag_part2 = s_exploit.recvline().strip().decode(); flag_parts.append(flag_part2)
            s_exploit.sendlineafter(b'[L] Logout', b'l')
            log.success(f"Lấy được phần 2: {flag_part2}")

            # Lấy phần 3
            s_exploit.sendlineafter(b'[Q] Quit', b'1'); s_exploit.sendlineafter(b'username:  ', b'Admin003')
            s_exploit.sendlineafter(b'key: ', admin_keys[2].encode()); s_exploit.recvuntil(b'Welcome,')
            s_exploit.sendlineafter(b'[L] Logout', b'1'); s_exploit.recvuntil(b'Your message: ')
            flag_part3 = s_exploit.recvline().strip().decode(); flag_parts.append(flag_part3)
            s_exploit.sendlineafter(b'[L] Logout', b'l')
            log.success(f"Lấy được phần 3: {flag_part3}")

            s_exploit.close()
            final_flag = "".join(flag_parts)
            print("\n" + "="*50); log.success(f"FLAG HOÀN CHỈNH: {final_flag}"); print("="*50)
            exit(0) # Thoát khi đã có flag
        else:
            log.warning(f"Offset {offset} không đúng.")
            s_exploit.close()

    except Exception as e:
        log.error(f"Lỗi ở offset {offset}: {e}")
        if 's_exploit' in locals() and s_exploit.connected():
            s_exploit.close()

log.error("Không tìm thấy offset đúng trong phạm vi. Thử tăng giới hạn brute-force.")