from utils.crypt import encrypt_flag, fetch_data

import requests
import hashlib
import multiprocessing
from functools import partial

DOMAIN = "passwords_as_keys"
DATA_DOMAIN = "https://gist.githubusercontent.com/wchargin/8927565/raw/d9783627c731268fb2935a731a618aa8e95cf465/words"

WORKERS = 10

def decrypt(cipher: str, hash: str, domain: str):
    response = requests.get(f"http://aes.cryptohack.org/{domain}/decrypt/{cipher}/{hash}/")

    
    if response.status_code != 200:
        print(response.text)
        raise Exception("Decryption Error")
    
    return response.json()["plaintext"]


def brute_force(ciphertext: str, words):
    print("started brute force")
    for word in words:
        run_single(ciphertext, word)


def run_single(ciphertext: str, word: str):
    try:
        hash_key = hashlib.md5(word.encode()).hexdigest()
        plaintext = decrypt(ciphertext, hash_key, domain=DOMAIN)
        try:
            plaintext = bytes.fromhex(plaintext).decode("utf-8")
            print(plaintext)
            if "cryp" in plaintext:
                print(f"Found match: {plaintext}")
                with open("output.txt", "w") as f:
                    f.write(plaintext)
        except:
            pass
            
    except Exception as e:
        print(f"An error occurred with word '{word}': {e}")


def brute_force_parallel(ciphertext: str, words: list):
    num_processes = multiprocessing.cpu_count()
    worker_function = partial(run_single, ciphertext)

    print(f"Starting brute force with {num_processes} workers")

    with multiprocessing.Pool(processes=num_processes) as pool:
        pool.map(worker_function, words)

    print("Brute force finished.")


def run(load=False):
    if load:
        words = fetch_data(DATA_DOMAIN)

        with open("words.txt", "w") as f:
            f.write(words)
    
    with open("words.txt") as f:
        words = [w.strip() for w in f.readlines()]

    
    ciphertext = encrypt_flag(DOMAIN)

    brute_force_parallel(ciphertext, words)

