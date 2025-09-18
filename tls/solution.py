import pyshark


PCAP_FILE_PATH = "tls/res/no-finished-tls3.cryptohack.org.pcapng"
SSL_KEYS_FILE_PATH = "tls/res/keylogfile.txt"

capture = pyshark.FileCapture(input_file=PCAP_FILE_PATH,
                              override_prefs={'tls.keylog_file': SSL_KEYS_FILE_PATH},
                              display_filter="http2.data")

print(len(capture))

for pkt in capture:
    if pkt.layers:
        try:
            print(pkt.layers[-1].data)
        except:
            print("couldnt do it..")
