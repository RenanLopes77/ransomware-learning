# File Encryption and Decryption

## Files in this Project

- `encrypt.py`: Python script to encrypt a text file.
- `decrypt.py`: Python script to decrypt a previously encrypted text file.
- `file.txt`: Example text file to be encrypted.
- `file.txt.locked`: The encrypted version of `file.txt` after encryption (generated by `encrypt.py`).
- `file.txt.unlocked`: The decrypted version of `file.txt` (generated by `decrypt.py`).
- `key_file.key`: File that contains the AES encryption key used to encrypt `file.txt`. This key is required for decryption.

## How to Use

### 1. Encrypting a File
`python encrypt.py <input_file> <output_encrypted_file> <key_file>`

This command will:

- Encrypt the content of file.txt.
- Save the encrypted content to file.txt.locked.
- Save the AES encryption key to key_file.key for later decryption.

**⚠️ Important:** Keep the key_file.key safe! You will need this key to decrypt the file.

### 2. Decrypting a File
`python decrypt.py <input_encrypted_file> <output_decrypted_file> <key_file>`

This command will:

- Decrypt the content of file.txt.locked using the key from key_file.key.
- Save the decrypted content to file.txt.unlocked
