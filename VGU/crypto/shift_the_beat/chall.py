import random

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

def shift_string(string, key):
    """
    Encrypts a string using a Caesar cipher with a unique shift for each character.

    Parameters:
    string (str): The string to be encrypted.
    key (list): A list of integer shifts, one for each character in the string.

    Returns:
    str: The encrypted string.
    """
    assert len(string) <= len(key)
    encrypted_string = ""
    for i in range(len(string)):
        # Shift each character by its corresponding key value
        encrypted_string += shift(string[i], key[i])
    return encrypted_string

# The FLAG is the secret string to be encrypted, but its value is hidden using "[REDACTED]".
# This placeholder is used for security purposes to prevent direct exposure of the FLAG value.
FLAG = "[REDACTED]"

# The `strings` list contains additional example strings to be encrypted.
# Each "[REDACTED]" is a placeholder for a unique value. 
# These placeholders do NOT imply that all strings have the same content.
strings = [
    "[REDACTED]", 
    "[REDACTED]", 
    "[REDACTED]", 
    "[REDACTED]", 
    "[REDACTED]", 
    "[REDACTED]", 
    "[REDACTED]", 
    "[REDACTED]", 
    "[REDACTED]", 
    "[REDACTED]"
]

# A random shift (key) is generated for each character in the FLAG.
# The key ensures a different shift for every character, providing stronger encryption.
key = [random.randint(1, 25) for _ in range(len(FLAG))]

# Encrypt the FLAG using the Caesar cipher and the generated key.
encrypted_flag = shift_string(FLAG, key)

# Encrypt each string in the `strings` list using the same key.
# This demonstrates how the same key can be applied to multiple inputs.
encrypted_strings = [shift_string(string, key) for string in strings]

# Output the encrypted FLAG and strings.
print(f'Encrypted Flag: {encrypted_flag}')
print(f'Encrypted Strings: {encrypted_strings}')

# NOTE:
# - The "[REDACTED]" placeholders indicate hidden values for security purposes.
# - The actual values of `FLAG` and each string in `strings` can differ.
# - This code assumes no knowledge of the underlying values for "[REDACTED]" is required.

#--------------------------------------------------------------------
#Encrypted Flag: gidijyqhy{tc1iu_1t_m0_czt_kadojn}
#Encrypted Strings: ["Oqw'e hrb xvdw bl", 
# 'Uwbz cqh hxj rg by, Hw upk fffg m', 
# 'Hguizvn ac oxh Wvzse Ujdx', 
# 'Ygekc yxa nt opkl cne xf qax gkoi', 
# 'hjjz j zvbezhiva cckwv lwfl nn', 
# "T bnzdugu'u xdwt rsm qxm dh", 
# 'Uwbz pryl nz d glgghy, bjpm f', 
# 'Qgnrtwp tm rqb ioxcnrz lwb wfmmoi', 
# "T'ur kn im texs zorx, 'lxi mmz ee", 
# 'Ewat mxzu gjh xwhz']