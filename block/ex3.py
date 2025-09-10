import requests

DOMAIN = "flipping_cookie"

def check_admin(domain: str, cookie: str, iv: str):
    response = requests.get(f"http://aes.cryptohack.org/{domain}/check_admin/{cookie}/{iv}")
    if response.status_code != 200:
        print(response.text)
        raise Exception("Encryption Error")
    
    response = response.json()
    if "flag" in response:
        return response["flag"]
    
    else:
        return "error"


def get_cookie(domain: str):
    response = requests.get(f"http://aes.cryptohack.org/{domain}/get_cookie/")
    if response.status_code != 200:
        print(response.text)
        raise Exception("Encryption Error")
    
    response = response.json()
    return response["cookie"]


def add(first, second):
    return bytes([a ^ b for a, b in zip(first, second)])


def run(load: bool = False):
    cookie          = "admin=False;expi"
    corrupt_cookie  = "admin=True;expir"

    target = add(cookie.encode(), corrupt_cookie.encode())

    cipher = get_cookie(DOMAIN)

    iv, cipher = cipher[:32], cipher[32:]

    corrupt_iv = add(bytes.fromhex(iv), target)

    print(check_admin(DOMAIN, cipher, corrupt_iv.hex()))
