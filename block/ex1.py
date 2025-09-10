from utils.crypt import encrypt_flag, decrypt
from aes.add_round_key import add

DOMAIN = "ecbcbcwtf"
    
def run():
    cipher = encrypt_flag(domain=DOMAIN)
    iv = cipher[:32]
    prev = iv

    res = ""

    for i in range(32, len(cipher), 32):
        block = cipher[i: i + 32]
        pt = bytes.fromhex(decrypt(block, domain=DOMAIN))
        prev = bytes.fromhex(prev)
        pt = add(pt, prev)

        res += pt.decode()
        prev = block
    
    print(res)