from utils.crypt import encrypt_flag, decrypt


DOMAIN = "block_cipher_starter"

def run():
    cipher = encrypt_flag(DOMAIN)
    plaintext = decrypt(cipher, DOMAIN)

    print(bytes.fromhex(plaintext))