def shift(char, num):
    """
    Shifts a character by a specified number of positions in the alphabet.
    Wraps around for alphabetic characters and leaves others unchanged.

    Parameters:
    char (str): A single character to be shifted.
    num (int): The number of positions to shift.

    Returns:
    str: The shifted character.
    """
    if char.isalpha():
        # Determine if the character is uppercase or lowercase
        base = ord('A') if char.isupper() else ord('a')
        # Perform the shift
        return chr((ord(char) - base + num) % 26 + base)
    else:
        # Non-alphabetic characters remain unchanged
        return char


def reverse_shift(encrypted_char, original_char):
    """
    Tìm số bước dịch chuyển từ `original_char` để được `encrypted_char`.
    """
    if original_char.isalpha():
        base = ord('A') if original_char.isupper() else ord('a')
        return (ord(encrypted_char) - ord(original_char)) % 26
    return 0

# Mã giải mã FLAG
def decode_flag(encrypted_string, key):
    decrypted_string = ""
    for i in range(len(encrypted_string)):
        decrypted_string += shift(encrypted_string[i], -key[i])  # Dịch ngược
    return decrypted_string

# Dữ liệu ban đầu
hint = "NeverGonnaGiveYouUpNeverGonna"
encrypted_hint = "UkbkxTtrvqSwxmFykOwYockgOwtjg"
encrypted_flag = "cmaiecmiz{h3tajr1y_m1zz_lzgj}"

# Tìm key từ hint
key = [reverse_shift(encrypted_hint[i], hint[i]) for i in range(len(hint))]

print(key, len(key))

# Giải mã FLAG
flag = decode_flag(encrypted_flag, key)
print(f"Decoded Flag: {flag}")
