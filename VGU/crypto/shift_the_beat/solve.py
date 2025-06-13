# key = []

# known = b'vgucypher{'
# ct = b'gidijyqhy{tc1iu_1t_m0_czt_kadojn}'
# #    b'I shouldn't
# #    b'T bnzdugu'u


# #    b'Ewat mxzu gjh xwhz
# #    b'Turn down for what'


# #    b'T'ur kn im texs zorx, 'lxi mmz ee

# #    b'I'll be by your side,



# #    b'Hguizvn ac oxh Wvzse Ujdx
# #    b'Welcome to the Hotel Cali



# ct_strings = ["Oqw'e hrb xvdw bl", 
# 'Uwbz cqh hxj rg by, Hw upk fffg m', 
# 'Hguizvn ac oxh Wvzse Ujdx', 
# 'Ygekc yxa nt opkl cne xf qax gkoi', 
# 'hjjz j zvbezhiva cckwv lwfl nn', 
# "T bnzdugu'u xdwt rsm qxm dh", 
# 'Uwbz pryl nz d glgghy, bjpm f', 
# 'Qgnrtwp tm rqb ioxcnrz lwb wfmmoi', 
# "T'ur kn im texs zorx, 'lxi mmz ee", 
# 'Ewat mxzu gjh xwhz']

# key = [(i-j)%26 for i, j in zip(ct, known)]


# print(key)

# key = key[:-1]


# def shift(char, num):
#     """
#     Shifts a character by a specified number of positions in the alphabet.
#     Wraps around for alphabetic characters and leaves others unchanged.

#     Parameters:
#     char (str): A single character to be shifted.
#     num (int): The number of positions to shift.

#     Returns:
#     str: The shifted character.
#     """
#     if char.isalpha():
#         # Determine if the character is uppercase or lowercase
#         base = ord('A') if char.isupper() else ord('a')
#         # Perform the shift
#         return chr((ord(char) - base - num) % 26 + base)
#     else:
#         # Non-alphabetic characters remain unchanged
#         return char

# def shift_string(string, key):
#     """
#     Encrypts a string using a Caesar cipher with a unique shift for each character.

#     Parameters:
#     string (str): The string to be encrypted.
#     key (list): A list of integer shifts, one for each character in the string.

#     Returns:
#     str: The encrypted string.
#     """
#     assert len(string) <= len(key)
#     encrypted_string = ""
#     for i in range(len(string)):
#         # Shift each character by its corresponding key value
#         encrypted_string += shift(string[i], key[i])
#     return encrypted_string








# pt_strings = []
# for i in ct_strings:
#     pt_strings.append(shift_string(i[:len(key)], key))

# print(pt_strings)



# key.append((ord(ct_strings[2][len(key)])-b'o'[0])%26)
# print(key)








# print(ct_strings[5][len(key)])
# key.append((ord(ct_strings[5][len(key)])-b't'[0])%26)
# print(key)





# known2 = b'or what'
# for i in range(7):
#     key.append((ord(ct_strings[-1][len(key)]) - known2[i]) % 26)


# print(key)





# key[13] = (ord(ct_strings[0][13]) - b't'[0]) % 26

# pt_strings = []
# for i in ct_strings:
#     pt_strings.append(shift_string(i[:len(key)], key))

# print(pt_strings)





# known2 = b'de'
# for i in range(len(known2)):
#     key.append((ord(ct_strings[-2][len(key)]) - known2[i]) % 26)

# print(key)






# known2 = b'gh'
# for i in range(len(known2)):
#     key.append((ord(ct_strings[-3][len(key)]) - known2[i]) % 26)

# print(key)




# known2 = b'ou'
# for i in range(len(known2)):
#     key.append((ord(ct_strings[5][len(key)]) - known2[i]) % 26)

# print(key)

# # Just the two of us, We can make i
# # Uwbz cqh hxj rg by, Hw upk fffg m
# known2 = b'an make i'
# for i in range(len(known2)):
#     key.append((ord(ct_strings[1][len(key)]) - known2[i]) % 26)

# print(key)




# # T'ur kn im texs zorx, 'lxi mmz ee
# # I'll be by your side, 'til the ea



# key[26] = (ord(ct_strings[4][26]) - b's'[0]) % 26


# key[31] = (ord(ct_strings[3][31]) - b'n'[0])%26



# pt_strings = []
# for i in ct_strings:
#     pt_strings.append(shift_string(i[:len(key)], key))

# print(pt_strings)


# ct = 'gidijyqhy{tc1iu_1t_m0_czt_kadojn}'
# recv_flag = shift_string(ct, key)

# print(recv_flag)
