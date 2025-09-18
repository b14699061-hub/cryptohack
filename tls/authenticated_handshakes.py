from scapy.all import rdpcap, conf
from scapy.layers.tls.all import TLS, TLSServerHello, TLSClientHello, TCP
from scapy.layers.tls import handshake

PCAP_FILE_PATH = "tls/res/no-finished-tls3.cryptohack.org.pcapng"
SSL_KEYS_FILE_PATH = "tls/res/keylogfile.txt"

def run():

    # Enable TLS decryption globally
    conf.tls_session_enable = True
    conf.tls_nss_filename = SSL_KEYS_FILE_PATH

    packets = rdpcap(PCAP_FILE_PATH)

    print(len(packets))

    server_hello: TLSServerHello | None = None
    client_hello: TLSClientHello = None

    for pkt in packets:
        if pkt.haslayer(TLS):
            tls = pkt[TLS]

            if tls.msg and isinstance(tls.msg[0], TLSServerHello):
                server_hello = tls.msg[0]
                print(server_hello.summary())

            elif tls.msg and isinstance(tls.msg[0], TLSClientHello):
                client_hello = tls.msg[0]
                print(client_hello.summary())

            else:
                print("#" * 10 + "\n")
                print(tls.summary())

        else:
            print(pkt.summary())

if __name__ == "__main__":
    run()
