from sage.all import *
from hashlib import sha256
from Crypto.Util.number import inverse

# Thêm import tường minh để tương thích với Sage 9.5
from sage.modules.free_module_integer import IntegerLattice

# --- Các tham số và giá trị đã biết ---
p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141

Q_x = 75734809163232403156751567099323868969251536315520212930406362087044311009812
Q_y = 59376216810615307969183220664321477461374978580814681880833956961200252954411
r = 75188570313431311860804303251549254089807291132108761029130443888999271228837
s = 28425244802253213823226413962559295239693382541446853572606143356013575587849

h_msg = b"Karmany-evadhikaras te ma phalesu kadacana ma karma-phala-hetur bhur ma te sango 'stv akarmani."
h = int(sha256(h_msg).hexdigest(), 16)

T = 2**128
h_msb = h >> 128

# Phương trình gốc: A*d_msb + B*d_lsb = C (mod n)
A = (s - r * T) % n
B = (-r) % n
C = (h - s * h_msb * T) % n

print("[+] Solving Hidden Number Problem via CVP...")

# Chuyển thành: d_lsb = V*d_msb + U (mod n)
try:
    B_inv = inverse(B, n)
except ValueError:
    print("[FAIL] B is not invertible modulo n. Cannot proceed.")
    exit()

V = (-A * B_inv) % n
U = (C * B_inv) % n

# --- Giải quyết bằng CVP ---
M = Matrix(ZZ, [
    [1, V],
    [0, n]
])
target_vector = vector(ZZ, [0, -U % n])
M_lll = M.LLL()
L = IntegerLattice(M_lll, lll_reduce=False)
closest_vector = L.closest_vector(target_vector)
solution_vector = closest_vector - target_vector

d_msb_candidate = solution_vector[0]
d_final = -1

for sign in [1, -1]:
    # Ép kiểu d_msb thành một số nguyên của Sage (ZZ) để tránh TypeError
    d_msb = ZZ(d_msb_candidate * sign)
    
    if d_msb <= 0:
        continue

    # Tính toán d_lsb dựa trên d_msb đã tìm được
    d_lsb = (V * d_msb + U) % n

    if 0 < d_msb < T and 0 < d_lsb < T:
        print(f"\n[+] Found potential solution:")
        print(f"  d_msb = {d_msb}")
        print(f"  d_lsb = {d_lsb}")

        d_candidate = (d_msb * T) + d_lsb
        
        E = EllipticCurve(GF(p), [0, 7])
        G = E(0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798, 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
        
        if int(d_candidate) * G == E(Q_x, Q_y):
            print("\n[SUCCESS] Verification successful! Private key `d` found.")
            d_final = d_candidate
            break

if d_final != -1:
    flag_content = sha256(str(d_final).encode()).hexdigest()
    flag = f"bi0sCTF{{{flag_content}}}"
    
    print("\n" + "="*50)
    print(f"FLAG: {flag}")
    print("="*50)
else:
    print("\n[FAIL] Could not find a valid solution with CVP.")