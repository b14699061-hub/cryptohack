import hmac
import hashlib
from aes.add_round_key import add

def hmac_sha256(key: bytes, message: bytes) -> str:
    block_size = 64  # SHA-256 block size is 512 bits (64 bytes)
    
    key = key.ljust(block_size, b'\x00')
    
    # Define inner and outer padding
    ipad = b'\x36' * block_size
    opad = b'\x5c' * block_size
    
    inner_key = add(key, ipad)
    inner_hash = hashlib.sha256(inner_key + message).digest()
    
    outer_key = add(key, opad)
    
    final_hmac = hashlib.sha256(outer_key + inner_hash).hexdigest()
    
    return final_hmac


def run():
    secret_key = b'my-super-secret-key'  
    data_to_authenticate = b'This is a test message for HMAC.'

    hmac_digest = hmac_sha256(secret_key, data_to_authenticate)
    print(f"Custom HMAC-SHA256 Digest: {hmac_digest}")


    built_in_hmac = hmac.new(secret_key, data_to_authenticate, hashlib.sha256).hexdigest()
    print(f"Built-in HMAC-SHA256 Digest: {built_in_hmac}")
