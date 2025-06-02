import streamlit as st
import logging
import time
import hashlib
import secrets
from copy import copy

logging.basicConfig(level=logging.CRITICAL,
                    format='%(asctime)s - %(levelname)s - %(message)s'
)

# --- RSA Implementation (from CSCI663Project_RSA.py) ---
def get_rsa_functions():
    def is_probably_prime(p, s=5):
        if p < 2: return False
        if p == 2 or p == 3: return True
        if p % 2 == 0: return False
        
        u = 0
        pminus1 = p - 1
        while pminus1 % 2 == 0:
            pminus1 //= 2
            u += 1
        r = pminus1
        
        for _ in range(s):
            a = secrets.randbelow(p - 2) + 2 # a in [2, p-2]
            z = pow(a, r, p)
            if (z != 1) and (z != p - 1):
                for _ in range(u - 1):
                    z = pow(z, 2, p)
                    if z == 1:
                        return False
                if z != p - 1:
                    return False
        return True

    def select_prime(l):
        while True:
            # Generate an odd number of the specified bit length
            n = (1 << (l - 1)) | secrets.randbits(l - 1) | 1
            if is_probably_prime(n):
                return n

    def eea(a, b):
        r = [a, b] if a > b else [b, a]
        s = [1, 0]
        t = [0, 1]
        i = 1
        while True:
            i += 1
            r.append(r[i-2] % r[i-1])
            q = (r[i-2] - r[i]) // r[i-1]
            s.append(s[i-2] - q * s[i-1])
            t.append(t[i-2] - q * t[i-1])
            if r[i] == 0:
                break
        return (r[i-1], s[i-1], t[i-1])

    def to_int(s):
        return int.from_bytes(s.encode('utf-8'), byteorder='little')

    def to_string(i):
        # Calculate the number of bytes needed
        num_bytes = (i.bit_length() + 7) // 8
        if num_bytes == 0: # Handle the case where i is 0
            num_bytes = 1
        try:
            return i.to_bytes(num_bytes, byteorder='little').decode('utf-8')
        except UnicodeDecodeError:
            # Fallback for cases where direct UTF-8 decode might fail (e.g., if the integer doesn't represent valid UTF-8)
            return f"Decrypted as integer: {i}"


    def rsa_generate_keys(pqlength):
        p = select_prime(pqlength)
        q = select_prime(pqlength)
        
        n = p * q
        phi_n = (p - 1) * (q - 1)
        while True:
            e = secrets.randbits(pqlength * 2)
            if e > 1 and e < phi_n: # e must be > 1 and < phi_n
                gcd_result = eea(e, phi_n)
                if gcd_result[0] == 1:
                    d = gcd_result[2]
                    # Ensure d is positive
                    d = d % phi_n
                    if d < 0:
                        d += phi_n
                    break
        return (n, e, d)

    def rsa_encrypt(plaintext, n, e, message_is_int):
        if message_is_int:
            try:
                msg_int = int(plaintext)
            except ValueError:
                return 'Error: Message is not a valid integer.'
        else:
            msg_int = to_int(plaintext)
        return pow(msg_int, e, n)

    def rsa_decrypt(ciphertext, n, d, message_is_int):
        try:
            cipher_int = int(ciphertext)
        except ValueError:
            return 'Error: Ciphertext is not a valid integer.'
        
        decrypted_int = pow(cipher_int, d, n)
        if message_is_int:
            return decrypted_int
        else:
            return to_string(decrypted_int)

    return rsa_generate_keys, rsa_encrypt, rsa_decrypt

generate_keys, encrypt_rsa, decrypt_rsa = get_rsa_functions()

# --- AES Implementation (from CSCI663Project_AES.py) ---
ROUND_CONSTANT = [
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
    0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
    0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
    0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
    0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
    0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
    0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b,
    0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
    0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
    0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
    0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
    0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
    0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
    0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63,
    0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
    0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb
]

SUBSTITUTION_BOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]

SUBSTITUTION_BOX_INVERSE = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
]


def rotate_word_bytes(word, n):
    return word[n:] + word[0:n]

def shift_rows(state):
    for i in range(4):
        state[i*4:i*4+4] = rotate_word_bytes(state[i*4:i*4+4], i)

def shift_rows_inverse(state):
    for i in range(4):
        state[i*4:i*4+4] = rotate_word_bytes(state[i*4:i*4+4], -i)

def key_schedule(word, i):
    new_word = []
    word = rotate_word_bytes(word, 1)
    for byte in word:
        new_word.append(SUBSTITUTION_BOX[byte])
    new_word[0] = new_word[0] ^ ROUND_CONSTANT[i]
    return new_word

def expandKey(cipher_key):
    cipher_key_size = len(cipher_key)
    assert cipher_key_size == 32

    current_size = 0
    expanded_key = []
    round_constant_index = 1
    expanded_key_next_4_bytes = [0, 0, 0, 0]

    for i in range(cipher_key_size):
        expanded_key.append(cipher_key[i])
    current_size += cipher_key_size

    while current_size < 240:
        for i in range(4):
            expanded_key_next_4_bytes[i] = expanded_key[(current_size - 4) + i]

        if current_size % cipher_key_size == 0:
            expanded_key_next_4_bytes = key_schedule(expanded_key_next_4_bytes, round_constant_index)
            round_constant_index += 1

        if current_size % cipher_key_size == 16:
            for i in range(4):
                expanded_key_next_4_bytes[i] = SUBSTITUTION_BOX[expanded_key_next_4_bytes[i]]

        for i in range(4):
            expanded_key.append(((expanded_key[current_size - cipher_key_size]) ^ (expanded_key_next_4_bytes[i])))
            current_size += 1
    return expanded_key

def substitution_bytes(state):
    for i in range(len(state)):
        state[i] = SUBSTITUTION_BOX[state[i]]

def substitution_bytes_inverse(state):
    for i in range(len(state)):
        state[i] = SUBSTITUTION_BOX_INVERSE[state[i]]

def galois_field_multiplation_table(a, b):
    p = 0
    for _ in range(8):
        if b & 1 == 1:
            p ^= a
        most_significant_bit = a & 0x80
        a <<= 1
        if most_significant_bit == 0x80:
            a ^= 0x1b
        b >>= 1
    return p % 256

def mix_column(column):
    temp_column = copy(column)
    column[0] = galois_field_multiplation_table(temp_column[0], 2) ^ galois_field_multiplation_table(temp_column[3], 1) ^ \
        galois_field_multiplation_table(temp_column[2], 1) ^ galois_field_multiplation_table(temp_column[1], 3)
    column[1] = galois_field_multiplation_table(temp_column[1], 2) ^ galois_field_multiplation_table(temp_column[0], 1) ^ \
        galois_field_multiplation_table(temp_column[3], 1) ^ galois_field_multiplation_table(temp_column[2], 3)
    column[2] = galois_field_multiplation_table(temp_column[2], 2) ^ galois_field_multiplation_table(temp_column[1], 1) ^ \
        galois_field_multiplation_table(temp_column[0], 1) ^ galois_field_multiplation_table(temp_column[3], 3)
    column[3] = galois_field_multiplation_table(temp_column[3], 2) ^ galois_field_multiplation_table(temp_column[2], 1) ^ \
        galois_field_multiplation_table(temp_column[1], 1) ^ galois_field_multiplation_table(temp_column[0], 3)

def mix_column_inverse(column):
    temp_column = copy(column)
    column[0] = galois_field_multiplation_table(temp_column[0], 14) ^ galois_field_multiplation_table(temp_column[3], 9) ^ \
        galois_field_multiplation_table(temp_column[2], 13) ^ galois_field_multiplation_table(temp_column[1], 11)
    column[1] = galois_field_multiplation_table(temp_column[1], 14) ^ galois_field_multiplation_table(temp_column[0], 9) ^ \
        galois_field_multiplation_table(temp_column[3], 13) ^ galois_field_multiplation_table(temp_column[2], 11)
    column[2] = galois_field_multiplation_table(temp_column[2], 14) ^ galois_field_multiplation_table(temp_column[1], 9) ^ \
        galois_field_multiplation_table(temp_column[0], 13) ^ galois_field_multiplation_table(temp_column[3], 11)
    column[3] = galois_field_multiplation_table(temp_column[3], 14) ^ galois_field_multiplation_table(temp_column[2], 9) ^ \
        galois_field_multiplation_table(temp_column[1], 13) ^ galois_field_multiplation_table(temp_column[0], 11)

def mix_columns(state):
    for i in range(4):
        column = [state[j*4+i] for j in range(4)]
        mix_column(column)
        for j in range(4):
            state[j*4+i] = column[j]

def mix_columns_inverse(state):
    for i in range(4):
        column = [state[j*4+i] for j in range(4)]
        mix_column_inverse(column)
        for j in range(4):
            state[j*4+i] = column[j]

def add_round_key(state, round_key):
    for i in range(len(state)):
        state[i] = state[i] ^ round_key[i]

def create_round_key(expanded_key, n):
    return expanded_key[(n*16):(n*16+16)]

def aes_round(state, round_key, round_number, aes_steps):
    substitution_bytes(state)
    aes_steps.append(f"Round Key {round_number} Byte Substitution: {state}")
    shift_rows(state)
    aes_steps.append(f"Round Key {round_number} Shift Rows: {state}")
    mix_columns(state)
    aes_steps.append(f"Round Key {round_number} Mix Columns: {state}")
    add_round_key(state, round_key)
    aes_steps.append(f"Round Key {round_number} Round Key Addition: {state}")

def aes_round_inverse(state, round_key, aes_steps):
    add_round_key(state, round_key)
    aes_steps.append(f"Inverse Round Key Addition: {state}")
    mix_columns_inverse(state)
    aes_steps.append(f"Inverse Mix Columns: {state}")
    shift_rows_inverse(state)
    aes_steps.append(f"Inverse Shift Rows: {state}")
    substitution_bytes_inverse(state)
    aes_steps.append(f"Inverse Byte Substitution: {state}")


def aes_rounds(state, expanded_key, aes_steps, num_rounds=14):
    round_key = create_round_key(expanded_key, 0)
    aes_steps.append(f"Initial Round Key: {round_key}")
    add_round_key(state, round_key)

    for i in range(1, num_rounds):
        round_key = create_round_key(expanded_key, i)
        aes_steps.append(f"Round Key {i}: {round_key}")
        aes_round(state, round_key, i, aes_steps)

    round_key = create_round_key(expanded_key, num_rounds)
    aes_steps.append(f"Final Round Key {num_rounds}: {round_key}")
    substitution_bytes(state)
    aes_steps.append(f"Final Round {num_rounds} Byte Substitution: {state}")
    shift_rows(state)
    aes_steps.append(f"Final Round {num_rounds} Shift Rows: {state}")
    add_round_key(state, round_key)
    aes_steps.append(f"Final Round {num_rounds} Round Key Addition: {state}")

def aes_rounds_inverse(state, expanded_key, aes_steps, num_rounds=14):
    round_key = create_round_key(expanded_key, num_rounds)
    aes_steps.append(f"Inverse Initial Round Key: {round_key}")
    add_round_key(state, round_key)
    aes_steps.append(f"Inverse Add Round Key: {state}")
    shift_rows_inverse(state)
    aes_steps.append(f"Inverse Shift Rows: {state}")
    substitution_bytes_inverse(state)
    aes_steps.append(f"Inverse Substitution Bytes: {state}")

    for i in range(num_rounds - 1, 0, -1):
        round_key = create_round_key(expanded_key, i)
        aes_steps.append(f"Inverse Round Key {i}: {round_key}")
        aes_round_inverse(state, round_key, aes_steps) # Pass aes_steps here

    round_key = create_round_key(expanded_key, 0)
    aes_steps.append(f"Inverse Final Round Key: {round_key}")
    add_round_key(state, round_key)
    aes_steps.append(f"Inverse Final Add Round Key: {state}")


def user_password_to_key(password):
    sha256 = hashlib.sha256()
    password_bytes = password.encode('latin-1')
    sha256.update(password_bytes)
    digest = sha256.digest()
    return [byte for byte in digest]

def aes_encrypt_or_decrypt_block(plaintext, key, aes_steps):
    block = copy(plaintext)
    aes_steps.append(f"Message block to process: {block}")
    expanded_key = expandKey(key)
    aes_rounds(block, expanded_key, aes_steps)
    aes_steps.append(f"Message block after AES rounds: {block}")
    return block

def get_string_next_16_characters(string_to_process, block_number, aes_steps):
    start_index = block_number[0] * 16
    end_index = start_index + 16
    chunk = string_to_process[start_index:end_index]

    if not chunk:
        return ""

    block = [ord(char) for char in chunk]

    if len(block) < 16:
        pad_char = 16 - len(block)
        block.extend([pad_char for _ in range(pad_char)])
    
    aes_steps.append(f"Block {block_number[0] + 1} (input): {block}")
    block_number[0] += 1
    return block

def encrypt_aes_string(string_to_encrypt, password, aes_steps_output):
    ciphertext_chars = []
    aes_steps = []

    initialization_vector = [185, 177, 50, 124, 65, 90, 169, 171,
                             201, 49, 140, 98, 166, 14, 214, 178]

    aes_key = user_password_to_key(password)
    aes_steps.append(f"Initial AES Key: {aes_key}")

    ciphertext_chars.extend([chr(i) for i in initialization_vector])

    file_size = len(string_to_encrypt)
    first_round = True
    block_number = [0]
    
    while True:
        block = get_string_next_16_characters(string_to_encrypt, block_number, aes_steps)
        if block == "":
            break

        if first_round:
            block_key = aes_encrypt_or_decrypt_block(initialization_vector, aes_key, aes_steps)
            first_round = False
        else:
            block_key = aes_encrypt_or_decrypt_block(block_key, aes_key, aes_steps)

        ciphertext_block = [block[i] ^ block_key[i] for i in range(16)]
        ciphertext_chars.extend([chr(i) for i in ciphertext_block])
        aes_steps.append(f"Ciphertext Block {block_number[0]} (output): {ciphertext_block}")

    if file_size % 16 == 0:
        ciphertext_chars.extend([chr(16)] * 16)
        aes_steps.append("Added final padding block.")

    aes_steps_output.extend(aes_steps) # Append steps to the provided list
    return "".join(ciphertext_chars)

def decrypt_aes_string(string_to_decrypt, password, aes_steps_output):
    plaintext_chars = []
    aes_steps = []

    aes_key = user_password_to_key(password)
    aes_steps.append(f"Initial AES Key: {aes_key}")

    block_number = [0]
    initialization_vector = get_string_next_16_characters(string_to_decrypt, block_number, aes_steps)
    if initialization_vector == "":
        aes_steps_output.extend(aes_steps)
        return "Error: Empty or invalid ciphertext (no IV found)."

    string_to_decrypt_actual_ciphertext = string_to_decrypt[16:]

    first_round = True
    block_number_ciphertext = [0] # Separate block number for actual ciphertext
    
    while True:
        block = get_string_next_16_characters(string_to_decrypt_actual_ciphertext, block_number_ciphertext, aes_steps)
        if block == "":
            break

        if first_round:
            block_key = aes_encrypt_or_decrypt_block(initialization_vector, aes_key, aes_steps)
            first_round = False
        else:
            block_key = aes_encrypt_or_decrypt_block(block_key, aes_key, aes_steps)

        plaintext_block = [block[i] ^ block_key[i] for i in range(16)]

        # Handle padding for the last block
        if block_number_ciphertext[0] * 16 >= len(string_to_decrypt_actual_ciphertext):
            # This is the last block of the actual ciphertext
            padding_value = plaintext_block[-1]
            if 1 <= padding_value <= 16: # Valid padding
                plaintext_block = plaintext_block[0:-padding_value]
            else: # Invalid padding, possibly corrupted or wrong key
                st.warning("Warning: Invalid padding detected. Decrypted content might be corrupted or the wrong key was used.")
        
        plaintext_chars.extend([chr(i) for i in plaintext_block])
        aes_steps.append(f"Plaintext Block {block_number_ciphertext[0]} (output): {plaintext_block}")

    aes_steps_output.extend(aes_steps) # Append steps to the provided list
    return "".join(plaintext_chars)

# --- Streamlit App Structure ---

st.set_page_config(layout="wide", page_title="Cryptography App", page_icon="🔐")

st.title("Cryptography App (AES & RSA)")

st.info("Please select your encryption method (AES or RSA) from the sidebar.")

# Initialize session state for RSA keys if they don't exist
if 'rsa_n' not in st.session_state:
    st.session_state.rsa_n, st.session_state.rsa_e, st.session_state.rsa_d = generate_keys(512 // 2)

# Sidebar for navigation
with st.sidebar:
    st.header("Cryptography")
    choice = st.radio(
        "Choose an encryption algorithm:",
        ("AES Encryption", "RSA Encryption")
    )
    st.markdown("---")
    st.subheader("About")
    st.info("""This application demonstrates AES (256-bit OFB mode) and RSA encryption/decryption algorithms.

Developed the encryption and decryption algorithms from scratch, creating a system that shows each step of the AES process, including the initial key, round keys, and ciphertext for each 16-byte block. The AES cipher uses a key size of 256 bits, and the RSA cipher can generate public key pairs (n, e) and private key pairs (n, d) with 80 or 128 bits.

© Copyright 2025, created by Jose Ambrosio""")

# Determine which section to display based on the radio button choice
if choice == "AES Encryption":
    aes_tab1, aes_tab2 = st.tabs(["AES Encrypt", "AES Decrypt"])

    with aes_tab1:
        # --- AES Encrypt Section ---
        st.header("AES Encrypt")
        st.write("Encrypt your message using AES (256-bit OFB mode).")

        aes_plaintext_input = st.text_area("Enter message to encrypt (AES):", height=150, key="aes_enc_input_text")
        aes_password_encrypt = st.text_input("Enter password for AES encryption:", type="password", key="aes_enc_password")

        if st.button("Encrypt (AES)", key="aes_encrypt_button"):
            if not aes_plaintext_input or not aes_password_encrypt:
                st.warning("Please enter both a message and a password to encrypt.")
            else:
                with st.spinner("Encrypting..."):
                    aes_encryption_steps = []
                    aes_ciphertext = encrypt_aes_string(aes_plaintext_input, aes_password_encrypt, aes_encryption_steps)
                    st.subheader("AES Encrypted Message (Latin-1 encoded):")
                    st.text_area("Ciphertext", aes_ciphertext, height=150, disabled=True, key="aes_enc_output_text")
                    
                    with st.expander("Show AES Encryption Steps"):
                        for step in aes_encryption_steps:
                            st.code(step)

    with aes_tab2:
        # --- AES Decrypt Section ---
        st.header("AES Decrypt")
        st.write("Decrypt your message using AES (256-bit OFB mode).")

        aes_ciphertext_input = st.text_area("Enter ciphertext to decrypt (AES):", height=150, key="aes_dec_input_text")
        aes_password_decrypt = st.text_input("Enter password for AES decryption:", type="password", key="aes_dec_password")

        if st.button("Decrypt (AES)", key="aes_decrypt_button"):
            if not aes_ciphertext_input or not aes_password_decrypt:
                st.warning("Please enter both ciphertext and a password to decrypt.")
            else:
                with st.spinner("Decrypting..."):
                    aes_decryption_steps = []
                    aes_decrypted_text = decrypt_aes_string(aes_ciphertext_input, aes_password_decrypt, aes_decryption_steps)
                    st.subheader("AES Decrypted Message:")
                    st.text_area("Plaintext", aes_decrypted_text, height=150, disabled=True, key="aes_dec_output_text")

                    with st.expander("Show AES Decryption Steps"):
                        for step in aes_decryption_steps:
                            st.code(step)

elif choice == "RSA Encryption":
    rsa_tab1, rsa_tab2, rsa_tab3 = st.tabs(["RSA Encrypt", "RSA Decrypt", "RSA Generate Keys"])

    with rsa_tab1:
        # --- RSA Encrypt Section ---
        st.header("RSA Encrypt")
        st.write("Encrypt your message using RSA.")

        # Options for using default or custom keys
        key_choice = st.radio(
            "Choose key source:",
            ("Use last generated keys", "Input custom keys"),
            key="rsa_encrypt_key_choice"
        )

        n_val_enc = st.session_state.rsa_n
        e_val_enc = st.session_state.rsa_e

        if key_choice == "Input custom keys":
            st.subheader("Custom RSA Keys for Encryption")
            n_input_enc = st.text_input("Enter n (Modulus):", key="rsa_enc_n_input")
            e_input_enc = st.text_input("Enter Public Key (e):", key="rsa_enc_e_input")
            if n_input_enc:
                try:
                    n_val_enc = int(n_input_enc)
                except ValueError:
                    st.error("Invalid input for n. Please enter an integer.")
                    n_val_enc = None
            if e_input_enc:
                try:
                    e_val_enc = int(e_input_enc)
                except ValueError:
                    st.error("Invalid input for e. Please enter an integer.")
                    e_val_enc = None
        else:
            st.subheader("Using Last Generated RSA Keys:")
            # Added unique keys here
            st.text_input("n (Modulus)", value=str(n_val_enc), disabled=True, key="rsa_enc_n_display_auto")
            st.text_input("Public Key (e)", value=str(e_val_enc), disabled=True, key="rsa_enc_e_display_auto")


        rsa_plaintext_input = st.text_area("Enter message to encrypt (RSA):", height=150, key="rsa_enc_input_text")
        
        rsa_encode_option = st.radio(
            "Message encoding option:",
            ("Convert message to bytes and then integer in little-endian order", "Message is already an integer"),
            key="rsa_encode_option"
        )
        message_is_int_enc = (rsa_encode_option == "Message is already an integer")


        if st.button("Encrypt (RSA)", key="rsa_encrypt_button"):
            if not rsa_plaintext_input:
                st.warning("Please enter a message to encrypt.")
            elif n_val_enc is None or e_val_enc is None:
                st.error("Please ensure n and e are valid integers.")
            else:
                with st.spinner("Encrypting..."):
                    rsa_ciphertext = encrypt_rsa(rsa_plaintext_input, n_val_enc, e_val_enc, message_is_int_enc)
                    st.subheader("RSA Encrypted Message:")
                    st.text_area("Ciphertext", str(rsa_ciphertext), height=150, disabled=True, key="rsa_enc_output_text")

    with rsa_tab2:
        # --- RSA Decrypt Section ---
        st.header("RSA Decrypt")
        st.write("Decrypt your ciphertext using RSA.")

        # Options for using default or custom keys
        key_choice = st.radio(
            "Choose key source:",
            ("Use last generated keys", "Input custom keys"),
            key="rsa_decrypt_key_choice"
        )

        n_val_dec = st.session_state.rsa_n
        d_val_dec = st.session_state.rsa_d

        if key_choice == "Input custom keys":
            st.subheader("Custom RSA Keys for Decryption")
            n_input_dec = st.text_input("Enter n (Modulus):", key="rsa_dec_n_input")
            d_input_dec = st.text_input("Enter Private Key (d):", key="rsa_dec_d_input")
            if n_input_dec:
                try:
                    n_val_dec = int(n_input_dec)
                except ValueError:
                    st.error("Invalid input for n. Please enter an integer.")
                    n_val_dec = None
            if d_input_dec:
                try:
                    d_val_dec = int(d_input_dec)
                except ValueError:
                    st.error("Invalid input for d. Please enter an integer.")
                    d_val_dec = None
        else:
            st.subheader("Using Last Generated RSA Keys:")
            # Added unique keys here
            st.text_input("n (Modulus)", value=str(n_val_dec), disabled=True, key="rsa_dec_n_display_auto")
            st.text_input("Private Key (d)", value=str(d_val_dec), disabled=True, key="rsa_dec_d_display_auto")

        rsa_ciphertext_input = st.text_area("Enter ciphertext to decrypt (RSA):", height=150, key="rsa_dec_input_text")

        rsa_decode_option = st.radio(
            "Message decoding option:",
            ("Convert decrypted message integer to bytes in little-endian order, then to string", "Keep message as integer"),
            key="rsa_decode_option"
        )
        message_is_int_dec = (rsa_decode_option == "Keep message as integer")

        if st.button("Decrypt (RSA)", key="rsa_decrypt_button"):
            if not rsa_ciphertext_input:
                st.warning("Please enter ciphertext to decrypt.")
            elif n_val_dec is None or d_val_dec is None:
                st.error("Please ensure n and d are valid integers.")
            else:
                with st.spinner("Decrypting..."):
                    rsa_decrypted_text = decrypt_rsa(rsa_ciphertext_input, n_val_dec, d_val_dec, message_is_int_dec)
                    st.subheader("RSA Decrypted Message:")
                    st.text_area("Plaintext", str(rsa_decrypted_text), height=150, disabled=True, key="rsa_dec_output_text")

    with rsa_tab3:
        # --- RSA Generate Keys Section ---
        st.header("RSA Key Generation")
        st.write("Generate a new pair of RSA public and private keys.")

        security_level_options = {
            '80 bit': 1024,
            '128 bit': 3072,
        }
        selected_security_level = st.selectbox(
            "Select Security Level (determines bit length for p and q):",
            list(security_level_options.keys()),
            key="rsa_security_level"
        )

        if st.button("Generate New RSA Keys", key="rsa_generate_button"):
            with st.spinner(f"Generating new keys for {selected_security_level} security level... This might take a moment."):
                pq_length = security_level_options[selected_security_level] // 2
                st.session_state.rsa_n, st.session_state.rsa_e, st.session_state.rsa_d = generate_keys(pq_length)
                st.success("New RSA keys generated successfully!")
                
        st.subheader("Current RSA Keys:")
        st.write(f"**n (Modulus):**")
        st.text_area("n_val", str(st.session_state.rsa_n), height=100, disabled=True, key="rsa_n_display") # Increased height
        st.write(f"**Public Key (e):**")
        st.text_area("e_val", str(st.session_state.rsa_e), height=100, disabled=True, key="rsa_e_display") # Increased height
        st.write(f"**Private Key (d):**")
        st.text_area("d_val", str(st.session_state.rsa_d), height=100, disabled=True, key="rsa_d_display") # Increased height



st.markdown("---")
st.markdown("© Copyright 2025, created by Jose Ambrosio")