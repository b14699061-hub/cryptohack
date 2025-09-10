from dh.utils.decrypt import decrypt_flag

# Intercepted from Alice:
m1 = \
    {
        "p": "0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 
        "g": "0x02", 
        "A": "0x344089bc5da357d429c9f17f98c893cabfce2794f1041c927481df421dae13ee81e211da2bdcd0b3c61b6c7079e68cb582c9bc584d6d7aad9b3f73eff03eae30357bb40b86742afde4d1e42c13b96982becee3f50c875b2bb42a80273c0f7669a64fe989b67698f5a52bfff55d28cfe8a619b0c4efe6c6da1a1806e9505f276b4453975306e5027c9a92abf233f86861baa4c8785202efcad39ca41c5bf4a5aab4b2516144a79011fc84f285dfa17b1109599eec16cb18374ca1d3c706ae2f96"
    }


# Intercepted from Bob:
m2 = \
    {
        "B": "0x22a2349c03f1684534c16347cf45eca74a6401d575df251e0788188e2fb32cccc13da34f63eb559f78f3a1af10e89848099bc298a8c68620e4129e166230367c01174d6445867a0ae1fc39cb7407861fbcea572e8a654e16a5171131d3039f040d9b9f5e2e006c09afd678564052bd7e7351a55e63f4cdaf422e3e42f5de7eba17d0f46c745b3fce99e3e73855f05b7a66c496cdfc768a6aff46f008b156f58b8d3906aec6307a35292fc47b0473c92a49b921396220e411764da87a6317c001"
    }


# Intercepted from Alice:
m3 = \
    {
        "iv": "d7995c5de809280260c430cf6feb3121",
        "encrypted": "4627c7188e0edb57253fbfdf29d6fad7e4b6c319ee7341b2e16c6a5c7edb0a33d8f1f6bb3d5d3cc2b7882794153bb0bf"
    }

def run():
    p = int(m1["p"], base=16)
    g = int(m1["g"], base=16)

    g_inv = p // g + 1

    A = int(m1["A"], base=16)
    B = int(m2["B"], base=16)

    shared_key = (A * B * g_inv) % p

    iv = m3["iv"]
    cipher = m3["encrypted"]

    plaintext = decrypt_flag(shared_key, iv, cipher)
    print(plaintext)