import hmac
import hashlib
import struct

from math import ceil


HASH_ALG = hashlib.sha384
HASH_LEN = HASH_ALG().digest_size


def tls_HMAC(k, b, algorithm):
    return bytearray(hmac.new(k, b, algorithm).digest())


def HKDF_expand(prk, info, length, algorithm):
    hash_len = algorithm().digest_size
    t = bytearray()
    okm = bytearray()
    for i in range(1, ceil(length / hash_len)+2):
        t = tls_HMAC(prk, t + info + bytearray([i]), algorithm)
        okm += t
    return okm[:length]


def HKDF_expand_label(secret, label, hashValue, length, algorithm):
    hkdfLabel = bytearray()
    hkdfLabel += struct.pack('>H', length)
    seq = bytearray(b"tls13 ") + label
    hkdfLabel += bytearray([len(seq)]) + seq
    seq = hashValue
    hkdfLabel += bytearray([len(seq)]) + seq

    return HKDF_expand(secret, hkdfLabel, length, algorithm)


def verify_data(finished_key, transcript, hash_alg):
    transcript_hash = hash_alg(transcript).digest()
    return tls_HMAC(finished_key, transcript_hash, hash_alg)


client_hello = bytes.fromhex("""
                    1603010200010001fc0303d8c7c79e62
                    892bd09bafe063b1f948880855589ef1
                    3eb847ca27e8436aa6ad8020e9319bcb
                    c7a532d08e0aa9597740d8467a3452ad
                    54693c6004d5e7e43fa37cd800b61302
                    13031301c02cc03000a3009fcca9cca8
                    ccaac0afc0adc0a3c09fc05dc061c057
                    c05300a7c02bc02f00a2009ec0aec0ac
                    c0a2c09ec05cc060c056c05200a6c024
                    c028006b006ac073c07700c400c3006d
                    00c5c023c02700670040c072c07600be
                    00bd006c00bfc00ac014003900380088
                    0087c019003a0089c009c01300330032
                    009a009900450044c0180034009b0046
                    009dc0a1c09dc051009cc0a0c09cc050
                    003d00c0003c00ba00350084002f0096
                    004100ff010000fd0000001800160000
                    13746c73332e63727970746f6861636b
                    2e6f7267000b000403000102000a0016
                    0014001d0017001e0019001801000101
                    010201030104337400000010000e000c
                    02683208687474702f312e3100160000
                    0017000000310000000d0030002e0403
                    05030603080708080809080a080b0804
                    08050806040105010601030302030301
                    020103020202040205020602002b0009
                    080304030303020301002d0002010100
                    3300260024001d0020f54b4d2a777319
                    ad3dc6cd8239025f24b547cce209feb5
                    b60aeaec25cb63af1b00150028000000
                    00000000000000000000000000000000
                    00000000000000000000000000000000
                    0000000000
                             """)

server_hello = bytes.fromhex("""
?
        """)

server_encrypted_extensions = bytes.fromhex("""
?
        """)

server_certificate_message = bytes.fromhex("""
?
        """)

server_certificateverify_message = bytes.fromhex("""
?
        """)

server_finished = bytes.fromhex("""
?
        """)


client_handshake_traffic_secret = bytes.fromhex("?")
finished_key = HKDF_expand_label(
    client_handshake_traffic_secret, b"finished", b"", HASH_LEN, HASH_ALG)

transcript = client_hello + server_hello + \
    server_encrypted_extensions + server_certificate_message + \
    server_certificateverify_message + server_finished

client_finished = verify_data(finished_key, transcript, HASH_ALG).hex()
print(client_finished)

