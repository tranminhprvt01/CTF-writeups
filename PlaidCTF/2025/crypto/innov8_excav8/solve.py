import subprocess
import z3
import struct

# Hàm exploit để xác định bit
def run_exploit(sequence):
    sequence = sequence[::-1]  # Đảo ngược vì LIFO
    solver = z3.Solver()
    se_state0, se_state1 = z3.BitVecs("se_state0 se_state1", 64)
    
    for i in range(len(sequence)):
        se_s1 = se_state0
        se_s0 = se_state1
        se_state0 = se_s0
        se_s1 ^= se_s1 << 23
        se_s1 ^= z3.LShR(se_s1, 17)
        se_s1 ^= se_s0
        se_s1 ^= z3.LShR(se_s0, 26)
        se_state1 = se_s1
        
        float_64 = struct.pack("d", sequence[i] + 1)
        u_long_long_64 = struct.unpack("<Q", float_64)[0]
        mantissa = u_long_long_64 & ((1 << 52) - 1)
        solver.add(int(mantissa) == z3.LShR(se_state0, 12))
    
    if solver.check() == z3.sat:
        model = solver.model()
        states = {state.__str__(): model[state] for state in model.decls()}
        state0 = states["se_state0"].as_long()
        u_long_long_64 = (state0 >> 12) | 0x3FF0000000000000
        float_64 = struct.pack("<Q", u_long_long_64)
        next_sequence = struct.unpack("d", float_64)[0] - 1
        return True, states, next_sequence
    else:
        return False, None, None

# Đọc output.txt
with open('output.txt', 'r') as f:
    output = [float(line.strip()) for line in f.readlines()]

# Kiểm tra độ dài
expected_length = 78 * 8 * 24  # 14,976 số
if len(output) != expected_length:
    print(f"Error: Expected {expected_length} numbers, got {len(output)}")
    exit(1)

# Tái tạo secretbits
num_bits = 78 * 8  # 624 bit
secretbits = ""

for i in range(num_bits):
    start = i * 24
    end = start + 24
    sequence = output[start:end]
    
    success, states, next_num = run_exploit(sequence)
    
    if success:
        secretbits += "1"
        print(f"Bit {i}: 1 - States: {states}, Next: {next_num}")
    else:
        secretbits += "0"
        print(f"Bit {i}: 0 - No solution")

# Chuyển secretbits về plaintext
secret = ""
for i in range(0, len(secretbits), 8):
    byte = secretbits[i:i+8]  # Lấy từng đoạn 8 bit
    if len(byte) == 8:  # Đảm bảo đủ 8 bit
        char = chr(int(byte, 2))  # Chuyển nhị phân về ký tự
        secret += char

# In kết quả
print("\nReconstructed secretbits:", secretbits)
print("Reconstructed plaintext:", secret)


# Reconstructed secretbits: 011001100110110001100001011001110011101000100000010100000100001101010100010001100111101101000010011101010110100101101100010001000011000101101110010001110101111101110110001110000101111101101001001101010101111101010011011101010100001101101000010111110011010001011111011100000110000100110001010011100010111000101110001011100111110100001010011100000110000101110011011100110111011101101111011100100110010000100000011101000110111100100000011100000110000101110010011101000010000000110010001110100010000001101111011000010111000100110001010011010100010000111001001100100110010101110110010100100111001101000100010110100111011001001000
# Reconstructed plaintext: flag: PCTF{BuilD1nG_v8_i5_SuCh_4_pa1N...}
# password to part 2: oaq1MD92evRsDZvH