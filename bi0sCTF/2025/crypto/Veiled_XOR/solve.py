import sys

# Tăng giới hạn đệ quy, cần thiết cho các phép toán trên số lớn
sys.setrecursionlimit(2000)

def extended_gcd(a, b):
    if a == 0: return (b, 0, 1)
    g, y, x = extended_gcd(b % a, a)
    return (g, x - (b // a) * y, y)

def modInverse(a, m):
    """Tìm nghịch đảo modular. Đây là công cụ cốt lõi cho việc cắt tỉa."""
    g, x, y = extended_gcd(a, m)
    if g != 1: raise Exception('Modular inverse does not exist')
    return x % m

def custom_long_to_bytes(n):
    if n == 0: return b'\x00'
    byte_string = b''
    while n > 0:
        byte_string = (n & 0xff).to_bytes(1, 'little') + byte_string
        n >>= 8
    if b'\x00' in byte_string:
        return byte_string[byte_string.find(b'\x00'):].lstrip(b'\x00')
    return byte_string

# --- Dữ liệu từ bài toán ---
n = 25650993834245004720946189793874326497984795849338302417110946799293291648040249066481025511053012034073848003478136002015789778483853455736405270138192685004206122168607287667373629714589814547144217162436740164024414206705483947822707673759856022882063396271521077034396144039740088690783163935477234001508676877728359035563304374705319120303835098697559771353065115371216095633826663393222290375210498159025443467666369652776698531368926392564476840557482790175694984871271075976052162527476586777386578254654222259777299785563550342986250558793337690540798983389913689337683350216697595855274995968459458553148267
c = 7874419222145223100478995004906732383469089972173454594282476506666095078687712494332749473566534625352139353593310707008146533254390514332880136585545606758108380402050369451711762195058199249765633645224407166178729834108159734540770902813439688437621416030538050164358987313607945402928893945400086827254622507315341530235984071126104731692679123171962413857123065243252313290356908958113679070546907527095194888688858140118665219670816655147095649132221436351529029926610142793850463533766705147562234382644751744682744799743855986811769162311342911946128543115444104102909314075691320520722623778914052878038508
veil_xor = 26845073698882094013214557201710791833291706601384082712658811014034994099681783926930272036664572532136049856667171349310624166258134687815795133386046337514685147643316723034719743474088423205525505355817639924602251866472741277968741560579392242642848932606998045419509860412262320853772858267058490738386
e = 65537
BIT_LEN = 1024

# --- Thuật toán Branch and Prune ---

# Khởi tạo tập ứng cử viên
p_start = (1 << (BIT_LEN - 1)) | 1
q_start = (1 << (BIT_LEN - 1)) | 1
solutions = {(p_start, q_start)}

# Lặp để xây dựng các bit
for k in range(1, BIT_LEN // 2):
    next_solutions = set()
    if not solutions:
        print(f"Thuật toán thất bại ở bước k={k}. Không còn ứng cử viên hợp lệ.")
        break
        
    # Với mỗi ứng cử viên (p, q) hợp lệ từ bước trước
    for p_guess, q_guess in solutions:
        
        # --- BƯỚC 1: PHÂN NHÁNH (BRANCH) ---
        # Ta sẽ brute-force bit `p_k` và suy ra các bit còn lại.
        # Đầu tiên, tính hằng số C = p_k ⊕ q_k từ n.
        L = k 
        p_low = p_guess & ((1 << L) - 1)
        q_low = q_guess & ((1 << L) - 1)
        C = ((n - p_low * q_low) >> L) & 1

        # Tạo ra 2 nhánh tương ứng với p_k = 0 và p_k = 1
        for p_k in [0, 1]:
            
            # --- BƯỚC 2: SUY DIỄN (DEDUCE) cho mỗi nhánh ---
            # Từ p_k, suy ra q_k.
            q_k = p_k ^ C
            
            # Từ p_k và q_k, suy ra các bit MSB tương ứng qua veil_xor.
            msb_idx = BIT_LEN - 1 - L
            p_msb = q_k ^ ((veil_xor >> msb_idx) & 1)
            q_msb = p_k ^ ((veil_xor >> L) & 1)
            
            # Tạo một ứng cử viên đầy đủ hơn cho nhánh này.
            p_next = p_guess | (p_k << L) | (p_msb << msb_idx)
            q_next = q_guess | (q_k << L) | (q_msb << msb_idx)
            
            # --- BƯỚC 3: CẮT TỈA NGAY LẬP TỨC (IMMEDIATE PRUNING) ---
            # Đây là bước kiểm tra mà bạn đề xuất.
            # Ta sẽ kiểm tra tính nhất quán của L+1 bit LSB.
            L_next = L + 1
            try:
                # Kiểm tra xem q_next có khớp với n * p_next⁻¹ (mod 2^L_next) không.
                p_inv = modInverse(p_next, 1 << L_next)
                q_check = (n * p_inv) & ((1 << L_next) - 1)
                
                q_deduced_low = q_next & ((1 << L_next) - 1)

                if q_check == q_deduced_low:
                    # Nếu nhánh này hợp lệ, giữ lại nó cho vòng lặp sau.
                    next_solutions.add((p_next, q_next))
                # Nếu không hợp lệ, ta không làm gì cả, tức là "chặt" nhánh đó đi.
            except Exception:
                # Lỗi không tìm thấy nghịch đảo (không nên xảy ra).
                pass
    
    # Cập nhật tập ứng cử viên. Kích thước của nó sẽ không tăng theo cấp số nhân.
    solutions = next_solutions
    # print(f"Bước k={k}, số lượng ứng cử viên còn lại: {len(solutions)}") # Bỏ comment để xem

# --- Xử lý kết quả ---
p, q = -1, -1
if solutions:
    p, q = list(solutions)[0]

if p != -1 and n == p * q:
    print("\nTHÀNH CÔNG!")
    print(f"Tìm thấy p: {p}")
    print(f"Tìm thấy q: {q}")
    phi = (p - 1) * (q - 1)
    d = modInverse(e, phi)
    m = pow(c, d, n)
    flag = custom_long_to_bytes(m)
    print(f"\nFlag: {flag.decode()}")
else:
    print("\nThất bại trong việc tìm p và q.")