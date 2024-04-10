import base64
import numpy as np
from hashlib import *


BLOCK_SIZE = 16

def get_private_key(voterid):
    # Read the key from file
    with open("key.txt", "rb") as file:
        key = file.read()

    password = str(sha256((voterid).encode('utf-8')).hexdigest())
    # Convert voterid to bytes
    salt = bytes(voterid, 'utf-8')

    # Derive the key using PBKDF2
    kdf = PBKDF2(password, salt, 64, 1000)

    # Extract the first 16 bytes of the derived key
    derived_key = kdf[:16]

    return derived_key

def encryptn(raw, private_key):
    print("Raw data:", raw)
    print("BLock size:", AES.block_size)
    raw = pad(raw, AES.block_size)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(private_key, AES.MODE_CBC, iv)
    return base64.b64encode(iv + cipher.encrypt(raw))

rcon = np.array([
        [0x01, 0x00, 0x00, 0x00],
        [0x02, 0x00, 0x00, 0x00],
        [0x04, 0x00, 0x00, 0x00],
        [0x08, 0x00, 0x00, 0x00],
        [0x10, 0x00, 0x00, 0x00],
        [0x20, 0x00, 0x00, 0x00],
        [0x40, 0x00, 0x00, 0x00],
        [0x80, 0x00, 0x00, 0x00],
        [0x1B, 0x00, 0x00, 0x00],
        [0x36, 0x00, 0x00, 0x00]
    ], dtype=np.uint8)


def read_sbox(file):
    s_box = [0] * 256
    try:
        with open(file, 'r') as f:
            index = 0
            for line in f:
                hex_values = line.split()
                for hex_value in hex_values:
                    if index >= 256:
                        break

                    s_box[index] = int(hex_value.strip(), 16)
                    index += 1
    except Exception as e:
        print("Error:", e)
    return s_box


def read_bytes(file):
    with open(file, 'r') as f:
        line = f.readline()
        hex_strings = line.split()
        return np.array([int(hex_str, 16) for hex_str in hex_strings], dtype=np.uint8)

def rot_word(word):
    return np.roll(word, -1)

def sub_word(word, sbox):
    return np.array([sbox[val] for val in word], dtype=np.uint8)

def expand_key(key, sbox):
    nr = 10
    nk = len(key) // 4
    w = np.zeros((4 * (nr + 1), 4), dtype=np.uint8)

    for i in range(nk):
        w[i] = key[4 * i: 4 * (i + 1)]

    i = nk
    while i < 4 * (nr + 1):
        temp = np.copy(w[i - 1])
        if i % nk == 0:
            temp = sub_word(rot_word(temp), sbox)
            temp ^= rcon[i // nk - 1]
        elif nk > 6 and i % nk == 4:
            temp = sub_word(temp, sbox)

        w[i] = w[i - nk] ^ temp
        i += 1

    return w


def encrypt(input, expanded_keys, sbox):
    state = [[0 for _ in range(4)] for _ in range(4)]

    for i in range(4):
        for j in range(4):
            state[i][j] = input[i + 4 * j]
    

    state = add_round_key(state, get_round_key(expanded_keys, 0))

    for r in range(1, 11):
        state = sub_bytes(state, sbox)
        state = shift_rows(state)

        if r <= 9:
            state = mix_columns(state)
            print("State after call", r, "to MixColumns()")
            print("----------------------------------------")
            for j in range(4):
                for i in range(4):
                    print("{:02x}".format(state[i][j]), end="  ")
                print("    ", end="")
            print("\n")
        state = add_round_key(state, get_round_key(expanded_keys, r))

    return state

def decrypt(cipher, expanded_keys, inv_sbox):
    for j in range(4):
        for i in range(4):
            print(format(cipher[i][j], '02x'), end='  ')
        print("    ")

    print("\n")
    state = add_round_key(cipher, get_round_key(expanded_keys, 10))  # Nr = 10



    for r in range(9, -1, -1):
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state, inv_sbox)
        state = add_round_key(state, get_round_key(expanded_keys, r))
        if r > 0:
            state = inv_mix_cols(state)

            print("State after call " + str(10 - r) + " to InvMixColumns()")
            print("----------------------------------------")
            for j in range(4):
                for i in range(4):
                    print("{:02x}".format(state[i][j]), end="  ")
                print("    ", end="")
            print("\n")

    return state


def add_round_key(state, round_key):
    for i in range(4):
        for j in range(4):
            state[i][j] ^= round_key[i][j]
    return state

def get_round_key(expanded_keys, r):
    round_key = [[0 for _ in range(4)] for _ in range(4)]
    for j in range(4):
        for i in range(4):
            round_key[i][j] = expanded_keys[4 * r + j][i]
    return round_key

def sub_bytes(state, sbox):
    for i in range(len(state)):
        for j in range(len(state[0])):
            state[i][j] = sbox[state[i][j] & 0xFF] 
    return state

def inv_sub_bytes(state, inv_sbox):
    for i in range(len(state)):
        for j in range(len(state[0])):
            state[i][j] = inv_sbox[state[i][j] & 0xFF]  # Ensure bytes are interpreted as unsigned
    return state


def shift_rows(state):
    new_state = [[0] * len(state[0]) for _ in range(len(state))]
    for i in range(len(state)):
        for j in range(len(state[0])):
            new_state[i][j] = state[i][(j + i) % 4]
    return new_state


def inv_shift_rows(state):
    new_state = [[0] * len(state[0]) for _ in range(len(state))]
    for i in range(len(state)):
        for j in range(len(state[0])):
            new_state[i][j] = state[i][(j - i + 4) % 4]
    return new_state


def mix_columns(state):
    
    new_state = [[0 for _ in range(4)] for _ in range(4)]

        
    for j in range(4):
        new_state[0][j] = (multiply_by_02(state[0][j]) ^ multiply_by_03(state[1][j]) ^ state[2][j] ^ state[3][j])
        new_state[1][j] = (state[0][j] ^ multiply_by_02(state[1][j]) ^ multiply_by_03(state[2][j]) ^ state[3][j])
        new_state[2][j] = (state[0][j] ^ state[1][j] ^ multiply_by_02(state[2][j]) ^ multiply_by_03(state[3][j]))
        new_state[3][j] = (multiply_by_03(state[0][j]) ^ state[1][j] ^ state[2][j] ^ multiply_by_02(state[3][j]))
    

            
    return new_state

def inv_mix_cols(state):
    new_state = [[0 for _ in range(4)] for _ in range(4)]
    for j in range(4):
        new_state[0][j] = (multiply_by_0e(state[0][j]) ^ multiply_by_0b(state[1][j]) ^ multiply_by_0d(state[2][j]) ^ multiply_by_09(state[3][j]))
        new_state[1][j] = (multiply_by_09(state[0][j]) ^ multiply_by_0e(state[1][j]) ^ multiply_by_0b(state[2][j]) ^ multiply_by_0d(state[3][j]))
        new_state[2][j] = (multiply_by_0d(state[0][j]) ^ multiply_by_09(state[1][j]) ^ multiply_by_0e(state[2][j]) ^ multiply_by_0b(state[3][j]))
        new_state[3][j] = (multiply_by_0b(state[0][j]) ^ multiply_by_0d(state[1][j]) ^ multiply_by_09(state[2][j]) ^ multiply_by_0e(state[3][j]))
    return new_state

def multiply_by_02(hex_value):
    result = hex_value << 1
    if (hex_value & 0x80) != 0:
        result ^= 0x1B
    return result & 0xFF

def multiply_by_03(hex_val):
    return multiply_by_02(hex_val) ^ hex_val

def multiply_by_09(hex):
        result = multiply_by_02(hex)
        result = multiply_by_02(result)
        result = multiply_by_02(result)
        return result ^ hex
    

def multiply_by_0b(hex):
    result = multiply_by_02(hex);
    result = multiply_by_02(result);
    result = result ^ hex;
    result = multiply_by_02(result);
    return result ^ hex

def multiply_by_0d(hex_val):
    result = multiply_by_02(hex_val)
    result = result ^ hex_val
    result = multiply_by_02(result)
    result = multiply_by_02(result)
    return result ^ hex_val

def multiply_by_0e(hex_val):
    result = multiply_by_02(hex_val)
    result = result ^ hex_val
    result = multiply_by_02(result)
    result = result ^ hex_val
    return multiply_by_02(result)

def main():
    sbox = read_sbox("sbox.txt")
    print(sbox)
    inv_sbox = read_sbox("inv_sbox.txt")
    key = read_bytes("key.txt")
    message = read_bytes("message.txt")
    expanded_keys = expand_key(key, sbox)

    print("Plaintext:")
    print(''.join([format(val, '02x') for val in message]))

    print("\nKey:")
    print(''.join([format(val, '02x') for val in key]))

    print("\nKey Schedule:")
    for i, round_key in enumerate(expanded_keys):
        if i % 4 == 0:
            print()
        print(''.join([format(val, '02x') for val in round_key]), end=", ")

    print("\n\nEncryption Process")
    print("------------------")
    print("Plain Text:")
    print(''.join([format(val, '02x') for val in message]))
    # for j in range(4):
    #             for i in range(4):
    #                 print("{:02x}".format(message[i][j]), end="  ")
    #             print("    ", end="")
    # print("\n")


    cipher = encrypt(message, expanded_keys, sbox)

    print("\nCipher Text:")
    for j in range(4):
                for i in range(4):
                    print("{:02x}".format(cipher[i][j]), end="  ")
                print("    ", end="")
    print("\n")
    #print(''.join([format(val, '02x') for val in cipher.tolist()]))
    
    print("\n\nDecryption Process")
    print("------------------")
    print("Cipher Text:")
    #print(''.join([format(val, '02x') for val in cipher.tolist()]))
    for j in range(4):
                for i in range(4):
                    print("{:02x}".format(cipher[i][j]), end="  ")
                print("    ", end="")
    print("\n")

    original_message = decrypt(cipher, expanded_keys, inv_sbox)

    print("\nPlain Text:")
    # print(''.join([format(val, '02x') for val in original_message]))
    for j in range(4):
                for i in range(4):
                    print("{:02x}".format(original_message[i][j]), end="  ")
    print("    ", end="")
if __name__ == "__main__":
    main()
