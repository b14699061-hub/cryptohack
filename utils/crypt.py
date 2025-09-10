import requests

def fetch_data(full_domain: str):
    response = requests.get(full_domain)
    if response.status_code != 200:
        raise Exception("Fetch Error")
    
    return response.text

def encrypt_flag(domain: str):
    response = requests.get(f"http://aes.cryptohack.org/{domain}/encrypt_flag/")
    if response.status_code != 200:
        raise Exception("Encryption Error")
    
    return response.json()["ciphertext"]



def decrypt(cipher: str, domain: str):
    response = requests.get(f"http://aes.cryptohack.org/{domain}/decrypt/{cipher}/")

    
    if response.status_code != 200:
        raise Exception("Decryption Error")
    
    return response.json()["plaintext"]


def break2blocks(data: str):
    return [data[i: i + 32] for i in range(0, len(data), 32)]