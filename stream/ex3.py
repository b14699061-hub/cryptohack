import requests
from enum import Enum
import string

from aes.add_round_key import add

DOMAIN = "ctrime"


def encrypt(domain: str, plaintext: str):
    response = requests.get(f"http://aes.cryptohack.org/{domain}/encrypt/{plaintext}/")

    if response.status_code != 200:
        print(response.text)
        raise Exception("Encryption Error")
    
    return response.json()["ciphertext"]


def run():
    # this is found by running this code with base = "crypto{"
    # crypto{CRIME_571ll_p4y5}
    base = b'571'

    for j in range(32):
        found = False
        for char in string.printable:
            base_len = len(encrypt(DOMAIN, base.hex()))

            cipher = encrypt(DOMAIN, (base + char.encode()).hex())
            
            if len(cipher) <= base_len:
                base += char.encode()
                print(base)
                found = True

        if not found:
            print("Could not find next char...")
            return
        


    print(base)

    

