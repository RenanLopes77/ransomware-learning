import os
import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from base64 import b64encode

# Key and IV generation (for simplicity, you can modify to be static or more secure)
def generate_key_iv():
    key = os.urandom(32)  # AES 256-bit key
    iv = os.urandom(16)   # AES block size is 16 bytes
    return key, iv

# Encrypt text file
def encrypt_file(input_file, output_file, key, iv, key_file):
    with open(input_file, 'rb') as f:
        plaintext = f.read()

    # Padding plaintext to ensure it's a multiple of AES block size
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    # AES Encryption (CBC mode)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Save the ciphertext and IV to the output file (base64-encoded)
    with open(output_file, 'wb') as f:
        f.write(b64encode(iv))  # Store the IV for later decryption
        f.write(b'\n')  # Separate IV from the actual ciphertext
        f.write(b64encode(ciphertext))  # Store the ciphertext

    # Save the key to a key file for later decryption
    with open(key_file, 'wb') as f:
        f.write(key)

    print(f'File encrypted and saved as {output_file}')
    print(f'Key saved as {key_file}')

def main():
    if len(sys.argv) != 4:
        print("Usage: python encrypt.py <input_file> <output_file> <key_file>")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]
    key_file = sys.argv[3]

    # Generate a random key and IV
    key, iv = generate_key_iv()

    # Encrypt the file
    encrypt_file(input_file, output_file, key, iv, key_file)

if __name__ == "__main__":
    main()

