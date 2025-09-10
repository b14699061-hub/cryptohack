import requests

from utils.crypt import encrypt_flag
from aes.add_round_key import add

DOMAIN = "symmetry"


def encrypt(domain: str, iv: str, plaintext: str):
    response = requests.get(f"http://aes.cryptohack.org/{domain}/encrypt/{plaintext}/{iv}/")

    if response.status_code != 200:
        print(response.text)
        raise Exception("Encryption Error")
    
    return response.json()["ciphertext"]
    
def run():
    cipher = encrypt_flag(domain=DOMAIN)
    iv, cipher = cipher[:32], cipher[32:]
    
    plaintext = (0).to_bytes(1).hex() * 16

    iv_cipher = encrypt(DOMAIN, iv, plaintext)
    iv_cipher_cipher = encrypt(DOMAIN, iv_cipher, plaintext)
    iv_cipher_cipher_cipher = encrypt(DOMAIN, iv_cipher_cipher, plaintext)

    flag = add(bytes.fromhex(cipher), bytes.fromhex(iv_cipher + iv_cipher_cipher + iv_cipher_cipher_cipher))

    print(flag)