import requests

DOMAIN = "ecb_oracle"

def encrypt(domain: str, plaintext: str):
    response = requests.get(f"http://aes.cryptohack.org/{domain}/encrypt/{plaintext}/")
    if response.status_code != 200:
        print(response.text)
        raise Exception("Encryption Error")
    
    return response.json()["ciphertext"]

def run():
    flag = ""
    for j in range(15, 0, -1):
        known_prefix = b"A" * j
        target_ciphertext = encrypt(DOMAIN, known_prefix.hex())[:32]
        
        found_byte = None
        for i in range(256):
            guessed_byte = bytes([i])
            test_plaintext = known_prefix + bytes.fromhex(flag) + guessed_byte
            test_ciphertext = encrypt(DOMAIN, test_plaintext.hex())[:32]
            
            if test_ciphertext == target_ciphertext:
                found_byte = i
                break
        
        if found_byte is not None:
            print(f"The next byte of the flag is: {hex(found_byte)}")
            flag += found_byte.to_bytes(1).hex()
        else:
            print("Could not find the next byte.")

    for j in range(11):
        known_prefix = b"A" * (16 - j)
        target_ciphertext = encrypt(DOMAIN, known_prefix.hex())[32:64]
        
        found_byte = None
        for i in range(256):
            guessed_byte = bytes([i])
            test_plaintext = bytes.fromhex(flag)[j:] + guessed_byte
            test_ciphertext = encrypt(DOMAIN, test_plaintext.hex())[:32]
            
            if test_ciphertext == target_ciphertext:
                found_byte = i
                break
        
        if found_byte is not None:
            print(f"The next byte of the flag is: {hex(found_byte)}")
            flag += found_byte.to_bytes(1).hex()
        else:
            print("Could not find the next byte.")

    print(bytes.fromhex(flag))
