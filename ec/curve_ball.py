from utils.socket import Client
import json

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

HOST = "socket.cryptohack.org" 
PORT = 13382

N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def run():
    
    client = Client(HOST, PORT)

    if client.connect():
        
        response = client.send_message("")
        print(response)

        message = \
        {
            "private_key": N + 1,
            "host": "www.bing.com",
            "curve": None,
            "generator": (0x3B827FF5E8EA151E6E51F8D0ABF08D90F571914A595891F9998A5BD49DFA3531, 0xAB61705C502CA0F7AA127DEC096B2BBDC9BD3B4281808B3740C320810888592A)
        }

        response = client.send_message(json.dumps(message))
        print(response)

        
    client.close()
