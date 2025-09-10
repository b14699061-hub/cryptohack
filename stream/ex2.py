import requests
from enum import Enum

from aes.add_round_key import add

DOMAIN = "bean_counter"


def encrypt(domain: str):
    response = requests.get(f"http://aes.cryptohack.org/{domain}/encrypt/")

    if response.status_code != 200:
        print(response.text)
        raise Exception("Encryption Error")
    
    return response.json()["encrypted"]

PNG_SIGN = b'\x89PNG\r\n\x1a\n'

class ChunkType(Enum):
    IHDR = "IHDR".encode("ascii")
    IDAT = "IDAT".encode("ascii")


def run():
    cipher = encrypt(DOMAIN)

    print(cipher[:32])

    sign = bytes.fromhex(cipher[:16])

    E = add(sign, PNG_SIGN)

    length_bytes = cipher[16:24]
    first_chunck_type = cipher[24: 32]

    length = 13
    E = E + add(bytes.fromhex(length_bytes), length.to_bytes(4)) + add(bytes.fromhex(first_chunck_type), ChunkType.IHDR.value)

    plaintext = b""
    for j in range(0, len(cipher), 32):
        chunk = cipher[j: j + 32]
        plaintext += add(E, bytes.fromhex(chunk))

    f = open("image.png", "wb")
    f.write(plaintext)
        
    print("Didnt find E...")

    

