import numpy as np
import sys

# Sử dụng pwnlib.log để in ra thông tin đẹp mắt
try:
    from pwn import *
    context.log_level = 'info'
except ImportError:
    class simple_log:
        def info(self, msg): print(f"[*] {msg}")
        def success(self, msg): print(f"[+] {msg}")
        def error(self, msg): print(f"[-] {msg}")
    log = simple_log()


def solve():
    n = 64

    # --- Bước 1: Tạo các hàng plaintext từ filler và đọc ciphertext ---
    log.info("Bước 1: Tạo các hàng plaintext và đọc ciphertext...")
    filler = "In cybersecurity, a CTF (Capture The Flag) challenge is a competitive, gamified event where participants, either individually or in teams, are tasked with finding and exploiting vulnerabilities in systems to capture hidden information known as flags. These flags are typically used to score points. CTFs test skills in areas like cryptography, web security, reverse engineering, and forensics, offering an exciting way to learn, practice, and showcase cybersecurity expertise.  This flag is for you: "
    filler_bits = "".join([bin(ord(i))[2:].zfill(8) for i in filler])
    
    all_p_rows = [list(map(int, list(filler_bits[i:i+n]))) for i in range(0, len(filler_bits) - n, n)]

    try:
        with open("encoded.txt", "r") as f:
            lines = f.readlines()
        all_c_rows = [list(map(int, line.strip().split())) for line in lines]
    except FileNotFoundError:
        log.error("Không tìm thấy file 'encoded.txt'.")
        return

    # --- Bước 2: Tìm một cơ sở (basis) gồm các cặp (p, c) độc lập tuyến tính ---
    log.info("Bước 2: Tìm một cơ sở độc lập tuyến tính...")
    p_basis_list = []
    c_basis_list = []
    indices_of_basis_vectors = []

    temp_p_basis = []
    for i in range(len(all_p_rows)):
        p_candidate = all_p_rows[i]
        
        temp_p_basis.append(p_candidate)
        rank = np.linalg.matrix_rank(np.array(temp_p_basis, dtype=np.float64))
        
        if rank > len(p_basis_list):
            p_basis_list.append(p_candidate)
            c_basis_list.append(all_c_rows[i])
            indices_of_basis_vectors.append(i)
        else:
            temp_p_basis.pop()
            
    rank_of_space = len(p_basis_list)
    log.success(f"Tìm thấy cơ sở gồm {rank_of_space} vector độc lập tuyến tính.")

    p_basis = np.array(p_basis_list, dtype=np.float64)
    c_basis = np.array(c_basis_list, dtype=np.float64)

    # --- Bước 3: Giải mã từng hàng ciphertext ---
    log.info("Bước 3: Giải mã từng hàng ciphertext bằng cách giải hệ phương trình tuyến tính...")
    
    p_full_reconstructed = []
    
    # Để giải A*x = b, ta cần A là ma trận vuông. 
    # Ta sẽ giải hệ c_i = X @ c_basis bằng cách chuyển vị: c_basis.T @ X.T = c_i.T
    # ma trận A là c_basis.T, x là X.T, b là c_i.T
    # Tuy nhiên, c_basis.T có kích thước 64x55, không phải vuông.
    # Ta phải dùng np.linalg.lstsq (Least Squares) để tìm nghiệm xấp xỉ tốt nhất.
    
    for c_i in all_c_rows:
        # Giải hệ c_i = X @ c_basis để tìm vector hệ số X
        #coeffs, residuals, rank, s = np.linalg.lstsq(c_basis.T, c_i, rcond=None)
        coeffs = np.linalg.lstsq(c_basis.T, c_i, rcond=None)[0]
        
        # Tái tạo hàng plaintext: p_i = X @ p_basis
        p_reconstructed_row = coeffs @ p_basis
        p_full_reconstructed.append(p_reconstructed_row)

    # Làm tròn toàn bộ kết quả về 0 hoặc 1
    p_full = np.rint(np.array(p_full_reconstructed)).astype(int)
    log.success("Đã tái tạo toàn bộ ma trận plaintext!")

    # --- Bước 4: Chuyển đổi về Flag ---
    log.info("Bước 4: Chuyển đổi bit về văn bản và trích xuất flag...")
    final_bit_string = "".join(map(str, p_full.flatten()))
    decoded_string = ""
    for i in range(0, len(final_bit_string), 8):
        byte = final_bit_string[i:i+8]
        if len(byte) < 8: continue
        try:
            decoded_string += chr(int(byte, 2))
        except ValueError: pass
            
    if filler in decoded_string:
        # Tìm vị trí chính xác và cắt chuỗi
        start_index = decoded_string.find(filler)
        flag = decoded_string[start_index + len(filler):].rstrip('\x00')
        print("\n" + "="*50)
        log.success(f"FLAG ĐÃ TÌM THẤY: {flag}")
        print("="*50)
    else:
        log.error("Giải mã thất bại. Chuỗi giải mã không chứa filler text.")
        print("Phần đầu chuỗi giải mã:", decoded_string[:200] + "...")

if __name__ == "__main__":
    solve()