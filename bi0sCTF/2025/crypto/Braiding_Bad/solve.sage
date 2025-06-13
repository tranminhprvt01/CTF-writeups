# -*- coding: utf-8 -*-
# LƯU Ý: Chạy bằng lệnh: sage solve.sage
# PHIÊN BẢN CUỐI CÙNG: Tấn công phân rã để khôi phục 'a', sau đó tính c2.

from Crypto.Util.number import long_to_bytes
import hashlib
import sys

#================================================================
#                      MAIN SCRIPT
#================================================================

print("[+] Bắt đầu giải quyết challenge bằng phương pháp Decomposition Attack cho 'a'...")

# Dữ liệu từ challenge bạn đã cung cấp
p_tietze = [50, 25, 40, 98, 35, 87, 54, 16, 65, 60, 95, 20, 4, 79, 69, 15, 53, 26, 92, 87, 48, 56, 99, 83, 2, 56, 47, 59, 42, 3, 19, 53]
q_tietze = [5, 24, 6, 21, 6, 28, 20, 48, 15, 18, 18, 8, 47, 22, 22, 3, 14, 40, 18, 26, 4, 31, 11, 16, 8, 46, 45, 23, 17, 39, 24, 21, 50, 25, 40, 98, 35, 87, 54, 16, 65, 60, 95, 20, 4, 79, 69, 15, 53, 26, 92, 87, 48, 56, 99, 83, 2, 56, 47, 59, 42, 3, 19, 53, -21, -24, -39, -17, -23, -45, -46, -8, -16, -11, -31, -4, -26, -18, -40, -14, -3, -22, -22, -47, -8, -18, -18, -15, -48, -20, -28, -6, -21, -6, -24, -5]
c1_tietze = [93, 84, 92, 90, 63, 63, 76, 60, 61, 57, 99, 62, 55, 91, 95, 62, 59, 54, 91, 69, 55, 60, 96, 74, 78, 55, 78, 64, 61, 54, 76, 84, 50, 25, 40, 98, 35, 87, 54, 16, 65, 60, 95, 20, 4, 79, 69, 15, 53, 26, 92, 87, 48, 56, 99, 83, 2, 56, 47, 59, 42, 3, 19, 53, -84, -76, -54, -61, -64, -78, -55, -78, -74, -96, -60, -55, -69, -91, -54, -59, -62, -95, -91, -55, -62, -99, -57, -61, -60, -76, -63, -63, -90, -92, -84, -93]
d = 2315157014596884429538745310505697576231247890652617038454441871904638642633138761681911931668903937398814215580589949726790160298882443329224130590117763020425392822361299940434853674756207376179949432149288134358028

# Bước 1: Khởi tạo
n = 100
B = BraidGroup(n)
p = B(p_tietze)
q = B(q_tietze)
c1 = B(c1_tietze)

# Bước 2: Tính k_a = q * p^-1 để khôi phục a
print("[+] Giai đoạn 1: Khôi phục 'a'...")
print("  -> Tính k_a = q * p^-1...")
k_a = q * p.inverse()

# Bước 3: Chiếu k_a xuống nhóm con bên trái để tìm a
print("  -> Chiếu k_a xuống nhóm con bên trái...")
k_a_tietze = k_a.Tietze()
# 'a' được tạo từ gs[:n//2-2] = gs[:48], chỉ số Tietze là 1..48.
a_tietze = [g for g in k_a_tietze if abs(g) <= (n/2 - 2)]
a = B(a_tietze)
print("[+] Đã khôi phục được braid 'a'!")

# Bước 4: Tính c2 theo công thức c2 = a * c1 * a^-1
print("\n[+] Giai đoạn 2: Tính c2 và giải mã...")
print("  -> Tính c2 = a * c1 * a^-1...")
c2 = a * c1 * a.inverse()

# Bước 5: Tính hash của c2 THEO ĐÚNG ĐỊNH NGHĨA
print("  -> Tính hash của dạng chuẩn của c2 (bước này có thể mất một chút thời gian)...")
h_obj = prod(c2.right_normal_form())
h = hashlib.sha512(str(h_obj).encode()).digest()

# Bước 6: Giải mã THEO ĐÚNG QUY TRÌNH
print("  -> Giải mã tin nhắn...")
# 6.1. Chuyển số nguyên d về chuỗi byte (độ dài thay đổi)
d_bytes_encoded = long_to_bytes(d)
# 6.2. Decode chuỗi byte đó bằng UTF-8 để lấy lại chuỗi ký tự
d_str = d_bytes_encoded
# 6.3. XOR giá trị của từng ký tự với hash để lấy lại message gốc
padded_message_bytes = bytes([c ^^ h_byte for c, h_byte in zip(d_str, h)])

# Bước 7: In kết quả
print("\n" + "="*50)
print("  FLAG:")
print("="*50)
try:
    # Tìm vị trí của dấu '}' để cắt chuỗi, vì flag thường có dạng bi0s{...}
    flag_start_index = padded_message_bytes.find(b'bi0s')
    if flag_start_index != -1:
        flag_end_index = padded_message_bytes.find(b'}', flag_start_index)
        if flag_end_index != -1:
            print(padded_message_bytes[flag_start_index : flag_end_index+1].decode())
        else:
            print(padded_message_bytes[flag_start_index:].decode())
    else:
        # Nếu không tìm thấy, in toàn bộ để debug
        print(padded_message_bytes.decode())
except Exception as e:
    print(f"Lỗi decode: {e}")
    print(padded_message_bytes)
print("="*50)