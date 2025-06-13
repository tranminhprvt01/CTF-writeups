from pwn import *
import json
from Crypto.Util.Padding import unpad

# Khởi tạo kết nối tới server (thay host và port nếu cần)
# p = process(["python3", "challenge.py"]) 
p = remote("43.204.144.100", 4001) # Ví dụ, thay bằng host/port của challenge

# Hàm helper để XOR hai chuỗi bytes
def xor(a, b):
    return bytes([x^y for x,y in zip(a,b)])


s='''
+----------------------------------------------------------+
|   ◦ APNA-AES v1.0 ◦                                      |
|   > Decryption protocol active                           |
|   > Encryption module: [offline]                         |
+----------------------------------------------------------+
'''
# Nhận banner
p.recvuntil(s)
p.recvline()
# Nhận token chứa thông điệp đã mã hóa
line = p.recvline().decode().strip()
# Trích xuất JSON từ chuỗi
token_json_str = line.split("Here is the encrypted message : ")[1]
token = json.loads(token_json_str)

# Decode các giá trị từ hex
iv1_orig = bytes.fromhex(token["IV1"])
iv2_orig = bytes.fromhex(token["IV2"])
ct_orig = bytes.fromhex(token["ciphertext"])

# Chia ciphertext gốc thành các khối 16-byte
blocks = [ct_orig[i:i+16] for i in range(0, len(ct_orig), 16)]
num_blocks = len(blocks)

log.info(f"Original IV1: {iv1_orig.hex()}")
log.info(f"Original IV2: {iv2_orig.hex()}")
log.info(f"Found {num_blocks} blocks of ciphertext.")

# Hàm chính để thực hiện padding oracle attack tìm một khối Decrypted_Block
def find_decrypted_block(input_to_aes):
    known_decrypted_bytes = b""
    iv2_attack = b'\x00' * 16 # IV2 không ảnh hưởng

    for i in range(1, 17): # Lặp 16 lần để tìm 16 byte
        padding_val = i
        # Tạo phần đuôi của IV1 giả mạo
        iv1_suffix = xor(known_decrypted_bytes, bytes([padding_val] * len(known_decrypted_bytes)))
        
        # Thử 256 giá trị cho byte cần tìm
        for g in range(256):
            # Tạo IV1 giả mạo hoàn chỉnh
            iv1_prefix = b'\x00' * (16 - len(iv1_suffix) - 1)
            iv1_guess_byte = bytes([g])
            iv1_attack = iv1_prefix + iv1_guess_byte + iv1_suffix
            
            # Tạo token để gửi đi
            payload = {
                "IV1": iv1_attack.hex(),
                "IV2": iv2_attack.hex(),
                "ciphertext": input_to_aes.hex()
            }
            
            # Gửi token và nhận kết quả
            p.sendlineafter(b"Enter token: ", json.dumps(payload).encode())
            response = p.recvline()
            
            # Kiểm tra xem padding có hợp lệ không
            if b"Valid padding" in response:
                # Nếu hợp lệ, ta đã tìm đúng byte
                decrypted_byte_val = g ^ padding_val
                known_decrypted_bytes = bytes([decrypted_byte_val]) + known_decrypted_bytes
                log.info(f"Found byte {16-i+1}/16: {hex(decrypted_byte_val)}")
                break # Thoát vòng lặp guess
        else:
            log.error("Could not find a valid padding byte. Something is wrong.")
            exit(1)
            
    log.success(f"Decrypted Block found: {known_decrypted_bytes.hex()}")
    return known_decrypted_bytes

# --- Bắt đầu quá trình giải mã ---
full_plaintext = b""
state1_prev = iv1_orig
state2_prev = iv2_orig

for i in range(num_blocks):
    log.info(f"--- Attacking Block {i+1}/{num_blocks} ---")
    current_c_block = blocks[i]
    
    # Tính toán input cho hàm AES_Decrypt của server
    # Input_Block_i = C_i XOR state2_trước_đó
    input_to_aes = xor(current_c_block, state2_prev)
    
    # Dùng padding oracle để tìm Decrypted_Block_i
    decrypted_block = find_decrypted_block(input_to_aes)
    
    # Tính toán Plaintext_Block_i
    # P_i = Decrypted_Block_i XOR state1_trước_đó
    plaintext_block = xor(decrypted_block, state1_prev)
    full_plaintext += plaintext_block
    
    log.success(f"Plaintext for block {i+1}: {plaintext_block}")
    
    # Cập nhật state cho vòng lặp tiếp theo
    state1_prev = input_to_aes
    state2_prev = decrypted_block
    
# --- Kết thúc giải mã ---

# Unpad để lấy message cuối cùng
try:
    flag = unpad(full_plaintext, 16)
    log.success(f"Decryption successful!")
    log.success(f"Flag: {flag.decode()}")
except ValueError as e:
    log.error(f"Failed to unpad the final plaintext: {e}")
    log.info(f"Full plaintext (with padding): {full_plaintext}")

p.close()