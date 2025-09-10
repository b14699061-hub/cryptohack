from aes.matrix import matrix2bytes

state = [
    [206, 243, 61, 34],
    [171, 11, 93, 31],
    [16, 200, 91, 108],
    [150, 3, 194, 51],
]

round_key = [
    [173, 129, 68, 82],
    [223, 100, 38, 109],
    [32, 189, 53, 8],
    [253, 48, 187, 78],
]

def add(first, second):
    return bytes([a ^ b for a, b in zip(first, second)])


def add_round_key(s, k) -> bytes:
    s_flat = matrix2bytes(s)
    k_flat = matrix2bytes(k)

    return add(s_flat, k_flat)


def run():
    print(add_round_key(state, round_key))

