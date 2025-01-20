import os
import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from base64 import b64decode

# Decrypt text file
def decrypt_file(input_file, output_file, key):
    with open(input_file, 'rb') as f:
        # Read the IV and ciphertext from the file
        iv = b64decode(f.readline().strip())  # Read the IV (first line)
        ciphertext = b64decode(f.read())  # Read the ciphertext (after the IV)

    # AES Decryption (CBC mode)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Unpadding the decrypted plaintext
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    # Save the decrypted content to the output file
    with open(output_file, 'wb') as f:
        f.write(plaintext)

    print(f'File decrypted and saved as {output_file}')

def main():
    if len(sys.argv) != 4:
        print("Usage: python decrypt.py <input_file> <output_file> <key_file>")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]
    key_file = sys.argv[3]

    # Load the key from the provided key file
    with open(key_file, 'rb') as f:
        key = f.read()

    # Decrypt the file
    decrypt_file(input_file, output_file, key)

if __name__ == "__main__":
    main()

