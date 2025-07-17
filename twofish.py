import ctypes

# Load Twofish shared library
lib = ctypes.CDLL("./libtwofish.so")

# Define argument and return types for Twofish encryption and decryption
lib.encrypt_bytes.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_char_p]
lib.encrypt_bytes.restype = ctypes.c_int

lib.decrypt_bytes.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_char_p]
lib.decrypt_bytes.restype = ctypes.c_int

BLOCK_SIZE = 16  # Twofish block size

def pad_twofish(plaintext):
    padding_length = BLOCK_SIZE - (len(plaintext) % BLOCK_SIZE)
    return plaintext + bytes([padding_length]) * padding_length

def unpad_twofish(plaintext):
    return plaintext[:-plaintext[-1]]

def encrypt_twofish(plaintext, key, iv):
    plaintext = pad_twofish(plaintext.encode('utf-8')) if isinstance(plaintext, str) else pad_twofish(plaintext)
    ciphertext = ctypes.create_string_buffer(len(plaintext))
    result = lib.encrypt_bytes(ctypes.c_char_p(plaintext), ctypes.c_int(len(plaintext)),
                               ctypes.c_char_p(key), ctypes.c_int(len(key)),
                               ctypes.c_char_p(iv), ciphertext)
    if result != 0:
        raise ValueError(f"Encryption failed: {result}")
    return ciphertext.raw

def decrypt_twofish(ciphertext, key, iv):
    plaintext = ctypes.create_string_buffer(len(ciphertext))
    result = lib.decrypt_bytes(ciphertext, len(ciphertext), key, len(key), iv, plaintext)
    if result != 0:
        raise ValueError(f"Decryption failed: {result}")
    return unpad_twofish(plaintext.raw)

