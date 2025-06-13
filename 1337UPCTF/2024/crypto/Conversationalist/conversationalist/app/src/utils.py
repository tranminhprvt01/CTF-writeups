from sage.all import GF

# modified from https://github.com/jvdsn/crypto-attacks/blob/master/attacks/gcm/forbidden_attack.py
x = GF(2)["x"].gen()
F = GF(2 ** 128, name="y", modulus=x ** 128 + x ** 7 + x ** 2 + x + 1)


# Converts an integer to a field element, little endian.
def int2field(n: int):
    return F([(n >> i) & 1 for i in range(127, -1, -1)])

# Converts a field element to an integer, little endian.
def field2int(f):
    # Lấy hệ số của đa thức f(x)
    coeffs = f.polynpmial().coefficients()

    # Khởi tạo một số nguyên n
    n = 0
    
    # Duyệt qua tất cả các hệ số từ cao đến thấp (big-endian)
    for i, coeff in enumerate(coeffs):
        if coeff == 1:
            # Chuyển hệ số thành bit tại vị trí i từ phía trái (big-endian)
            n |= (1 << (127 - i))  # Lấy vị trí bit từ 127 xuống 0
    
    return n




# Calculates the AES-GCM GHASH polynomial.
def ghash(h, a: bytes, c: bytes):
    la  = len(a) # Associated Data length
    lc  = len(c) # Ciphertext length

    # Compute the GHASH polynomial
    res = int2field(0)

    # Process the associated data
    for i in range(la // 16):
        res += int2field(int.from_bytes(a[16 * i:16 * (i + 1)], byteorder="big"))
        res *= h
    
    # Process the last block of associated data
    if la % 16 != 0:
        res += int2field(int.from_bytes(a[-(la % 16):] + bytes(16 - la % 16), byteorder="big"))
        res *= h
    
    # Process the ciphertext
    for i in range(lc // 16):
        res += int2field(int.from_bytes(c[16 * i:16 * (i + 1)], byteorder="big"))
        res *= h
    
    # Process the last block of ciphertext
    if lc % 16 != 0:
        res += int2field(int.from_bytes(c[-(lc % 16):] + bytes(16 - lc % 16), byteorder="big"))
        res *= h
    
    # Process the length of the associated data and ciphertext
    res += int2field(((8 * la) << 64) | (8 * lc))
    res *= h

    return res