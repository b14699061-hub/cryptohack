from scapy.all import rdpcap
from scapy.layers.tls.all import TLS, TLSServerHello, encry

PCAP_FILE_PATH = "tls/res/no-finished-tls3_642a73844a64e902ef6c8564972e98ca.cryptohack.org.pcapng"

def run():
    packets = rdpcap(PCAP_FILE_PATH)

    server_hello = None

    for pkt in packets:
        if pkt.haslayer(TLS):
            tls = pkt[TLS]
            if tls.msg and isinstance(tls.msg[0], TLSServerHello):
                print(tls.msg[0].summary())
                print(type(tls.msg[0]))

                server_hello = tls.msg[0]

if __name__ == "__main__":
    run()
