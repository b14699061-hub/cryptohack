from utils.socket import Client
import json

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

HOST = "socket.cryptohack.org" 
PORT = 13388

TARGET = b"admin=True"

EMPTY_BLOCK = b"" # b"\x00" * 16


def bxor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def hash(data, known_hash):
    data = pad(data, 16)
    out = known_hash
    for i in range(0, len(data), 16):
        blk = data[i:i+16]
        out = bxor(AES.new(blk, AES.MODE_ECB).encrypt(out), out)
    return out

def compress(state, block):
    """One round of the toy hash compression function"""
    tmp = AES.new(block, AES.MODE_ECB).encrypt(state)
    return bxor(tmp, state)

def extend(tag, extra):
    """
    Perform length extension: given the tag = Hash(K||M),
    produce Hash(K||M||extra) without knowing K.
    """
    # Pad extra to 16-byte blocks
    extra = pad(extra, 16)
    state = tag
    for i in range(0, len(extra), 16):
        blk = extra[i:i+16]
        state = compress(state, blk)
    return state


def run():

    message1 = \
        {
            "option": "sign",
            "message": EMPTY_BLOCK.hex()
        }
    
    example_message = \
        {
            "option": "sign",
            "message": (EMPTY_BLOCK + b"test").hex()
        }

    final_message = \
        {
            "option": "get_flag",
            "signature": 0,
            "message": TARGET.hex()
        }
    
    client = Client(HOST, PORT)

    if client.connect():
        
        response = client.send_message("")
        print(response)

        response1 = client.send_message(json.dumps(message1))
        sign1 = bytes.fromhex(json.loads(response1)["signature"])
        print(response1)

        # test:
        example_response = client.send_message(json.dumps(example_message))
        example_sign = bytes.fromhex(json.loads(example_response)["signature"])
        print(example_response)

        print(f"example signature: {example_sign.hex()}")

        print(f"fabricated signature: {extend(sign1, bytes.fromhex(example_message["message"])).hex()}")

        print(f"starting signature: {sign1.hex()}")

        
        final_sign = hash(TARGET, sign1)
        
        final_message["signature"] = final_sign.hex()

        print(final_message)
        final_response = client.send_message(json.dumps(final_message))
        print(final_response)

    client.close()
