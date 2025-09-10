from dh.utils.decrypt import decrypt_flag


def run():
    # change g and A to 0x01 and thats about it... your aes key will be 0x01
    response = {"iv": "a2d457b7514a41ae725b3d2c66c2dd30", "encrypted_flag": "08b2c927101d4f56efff1031358dfe087d4f6de31307b8c818e629ad6e0c7bc9"}
    
    plaintext = decrypt_flag(1, response["iv"], response["encrypted_flag"])

    print(plaintext)