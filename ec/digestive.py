import json
import requests

DOMAIN = "digestive"


def sign(domain: str, username: str):
    response = requests.get(f"http://aes.cryptohack.org/{domain}/sign/{username}")
    if response.status_code != 200:
        raise Exception("Encryption Error")
    
    return response.json()



def verify(domain: str, message: str, signature: str):
    response = requests.get(f"http://aes.cryptohack.org/{domain}/verify/{message}/{signature}")

    
    if response.status_code != 200:
        raise Exception("Decryption Error")
    
    return response.json()


def hash(message: str, admin: bool = False):
    msg = json.dumps({"admin": admin, "username": message})
    return msg.encode()

def run():


    username = "blabla"
    
    response = sign(DOMAIN, username)

    message = '{"admin": false, "username": "blabla", "admin": true}'
    signature = response["signature"]
    response = verify(DOMAIN, message, signature)

    print(response["flag"])