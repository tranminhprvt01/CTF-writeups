import base64
import hashlib
from cryptography.fernet import Fernet
import string


# Function to generate a key from the password
def generate_key(password):
    password_bytes = password.encode('utf-8')
    key = hashlib.sha256(password_bytes).digest()  # SHA256 to get a 32-byte key
    return base64.urlsafe_b64encode(key)


# # Function to decrypt data with a given key
# def decrypt_data(ciphertext, key):
#     try:
#         cipher = Fernet(key)
#         decrypted_data = cipher.decrypt(ciphertext)
#         # Check if the decrypted data is readable
#         if all(chr(c) in string.printable for c in decrypted_data):
#             return decrypted_data.decode("utf-8")  # Successfully decrypted
#     except Exception:
#         return None  # Decryption failed
#     return None

# Function to decrypt data with a given key
def decrypt_data(ciphertext, key):
    try:
        cipher = Fernet(key)
        decrypted_data = cipher.decrypt(ciphertext)
        # Check if the decrypted data is readable
        print(decrypt_data)
        if all(chr(c) in string.printable for c in decrypted_data):
            return decrypted_data.decode("utf-8")  # Successfully decrypted
    except Exception:
        return None  # Decryption failed
    return None



# Main function for brute-forcing
def brute_force_decrypt(ciphertext, years, countries):
    for year in years:
        for country in countries:
            password = f"{year}{country.lower()}"
            key = generate_key(password)
            decrypted_text = decrypt_data(ciphertext, key)
            print(decrypted_text)
            if decrypted_text:
                print(f"Success! Key: {password}")
                print(f"Decrypted text: {decrypted_text}")
                return
    print("Failed to decrypt the ciphertext.")


# List of years and countries
years = [str(year) for year in range(1950, 2025)]
countries = [
    "Afghanistan", "Albania", "Algeria", "Andorra", "Angola", "Antigua and Barbuda", "Argentina", "Armenia", "Australia", "Austria", 
    "Azerbaijan", "Bahamas", "Bahrain", "Bangladesh", "Barbados", "Belarus", "Belgium", "Belize", "Benin", "Bhutan", 
    "Bolivia", "Bosnia and Herzegovina", "Botswana", "Brazil", "Brunei", "Bulgaria", "Burkina Faso", "Burundi", "Cabo Verde", "Cambodia", 
    "Cameroon", "Canada", "Central African Republic", "Chad", "Chile", "China", "Colombia", "Comoros", "Congo (Congo-Brazzaville)", 
    "Costa Rica", "Croatia", "Cuba", "Cyprus", "Czechia (Czech Republic)", "Denmark", "Djibouti", "Dominica", "Dominican Republic", 
    "Ecuador", "Egypt", "El Salvador", "Equatorial Guinea", "Eritrea", "Estonia", "Eswatini (fmr. Swaziland)", "Ethiopia", "Fiji", 
    "Finland", "France", "Gabon", "Gambia", "Georgia", "Germany", "Ghana", "Greece", "Grenada", "Guatemala", "Guinea", 
    "Guinea-Bissau", "Guyana", "Haiti", "Holy See", "Honduras", "Hungary", "Iceland", "India", "Indonesia", "Iran", "Iraq", 
    "Ireland", "Israel", "Italy", "Jamaica", "Japan", "Jordan", "Kazakhstan", "Kenya", "Kiribati", "Korea (North)", "Korea (South)", 
    "Kuwait", "Kyrgyzstan", "Laos", "Latvia", "Lebanon", "Lesotho", "Liberia", "Libya", "Liechtenstein", "Lithuania", 
    "Luxembourg", "Madagascar", "Malawi", "Malaysia", "Maldives", "Mali", "Malta", "Marshall Islands", "Mauritania", "Mauritius", 
    "Mexico", "Micronesia", "Moldova", "Monaco", "Mongolia", "Montenegro", "Morocco", "Mozambique", "Myanmar (formerly Burma)", 
    "Namibia", "Nauru", "Nepal", "Netherlands", "New Zealand", "Nicaragua", "Niger", "Nigeria", "North Macedonia (formerly Macedonia)", 
    "Norway", "Oman", "Pakistan", "Palau", "Palestine State", "Panama", "Papua New Guinea", "Paraguay", "Peru", "Philippines", 
    "Poland", "Portugal", "Qatar", "Romania", "Russia", "Rwanda", "Saint Kitts and Nevis", "Saint Lucia", "Saint Vincent and the Grenadines", 
    "Samoa", "San Marino", "Sao Tome and Principe", "Saudi Arabia", "Senegal", "Serbia", "Seychelles", "Sierra Leone", "Singapore", 
    "Slovakia", "Slovenia", "Solomon Islands", "Somalia", "South Africa", "South Sudan", "Spain", "Sri Lanka", "Sudan", 
    "Suriname", "Sweden", "Switzerland", "Syria", "Tajikistan", "Tanzania", "Thailand", "Timor-Leste", "Togo", "Tonga", 
    "Trinidad and Tobago", "Tunisia", "Turkey", "Turkmenistan", "Tuvalu", "Uganda", "Ukraine", "United Arab Emirates", 
    "United Kingdom", "United States of America", "Uruguay", "Uzbekistan", "Vanuatu", "Venezuela", "Vietnam", "Yemen", 
    "Zambia", "Zimbabwe"
]



# for _ in range(1, 4):
#     # Load the ciphertext from the encrypted file
#     with open(f"encrypted_friend{_}.txt", "rb") as encrypted_file:
#         ciphertext = encrypted_file.read()

#     # Brute force the decryption key
#     brute_force_decrypt(ciphertext, years, countries)


# Load the ciphertext from the encrypted file
with open("encrypted_friend2.txt", "rb") as encrypted_file:
    ciphertext = encrypted_file.read()

# Brute force the decryption key
brute_force_decrypt(ciphertext, years, countries)