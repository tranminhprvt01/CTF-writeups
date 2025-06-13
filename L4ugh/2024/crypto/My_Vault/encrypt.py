import base64
import hashlib

from cryptography.fernet import Fernet


# Function to generate a key from the password
def generate_key(password):
    # Hash the password to generate a consistent key
    password_bytes = password.encode('utf-8')
    key = hashlib.sha256(password_bytes).digest()  # SHA256 to get a 32-byte key
    return base64.urlsafe_b64encode(key)  # Fernet requires the key to be in base64 format

# Function to encrypt the file
def encrypt_file(file_name, password):
    # Generate a key based on the password
    key = generate_key(password)
    cipher = Fernet(key)

    # Read the original file content
    with open(file_name, 'rb') as file:
        file_data = file.read()

    # Encrypt the data
    encrypted_data = cipher.encrypt(file_data)

    # Save the encrypted content to a new file
    with open(f"encrypted_{file_name}", 'wb') as encrypted_file:
        encrypted_file.write(encrypted_data)

    print(f"File encrypted successfully! Encrypted file saved as 'encrypted_{file_name}'.")

# Main script
def main():
    # Prompt the user for file name and password
    file_name = input("Enter the file name to encrypt: ")
    password = input("Enter the password to use for encryption: ")

    # Encrypt the file
    encrypt_file(file_name, password)

if __name__ == "__main__":
    main()
