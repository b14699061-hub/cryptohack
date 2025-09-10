import requests

DOMAIN = "lazy_cbc"


def encrypt(domain:str, plaintext: str):
    response = requests.get(f"http://aes.cryptohack.org/{domain}/encrypt/{plaintext}/")
    if response.status_code != 200:
        print(response.text)
        raise Exception("Encryption Error")
    
    response = response.json()
    
    if "error" in response:
        return "error"

    return response["ciphertext"]


def get_flag(domain: str, key: str):
    response = requests.get(f"http://aes.cryptohack.org/{domain}/get_flag/{key}/")
    if response.status_code != 200:
        print(response.text)
        raise Exception("Encryption Error")
    
    response = response.json()
    
    if "plaintext" in response:
        return response["plaintext"]
    
    else:
        return "error"


def receive(domain: str, ciphertext: str):
    response = requests.get(f"http://aes.cryptohack.org/{domain}/receive/{ciphertext}/")
    if response.status_code != 200:
        print(response.text)
        raise Exception("Encryption Error")
    
    response = response.json()
    
    if "error" in response:
        return response["error"]

    return "success"


def add(first, second):
    return bytes([a ^ b for a, b in zip(first, second)])


def run(load: bool = False):
    plaintext = (0).to_bytes(1).hex() * 16

    ciphertext = encrypt(DOMAIN, plaintext)

    response = receive(DOMAIN, ciphertext)
    if response == "success":
        print("The starting plaintext is invalid - WHICH IS NOT GOOD!")
    
    secod_block = (0).to_bytes(1).hex() * 16

    third_block = ciphertext

    forth_block = (255).to_bytes(1).hex() * 16

    res = receive(DOMAIN, ciphertext + secod_block + third_block + forth_block)
    print(res.split())

    key = res.split(" ")[2][64:96]
    print(key)
    
    flag = get_flag(DOMAIN, key)

    print(bytes.fromhex(flag))
