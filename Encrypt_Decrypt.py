from Crypto.Cipher import AES, Blowfish, DES3
from Crypto.Util.Padding import pad, unpad
from utility import *
from twofish import *



        
def encrypt_text(algorithm, key, block_size, plaintext,iv):
    cipher = algorithm.new(key, algorithm.MODE_CBC,iv)
    ciphertext = cipher.iv + cipher.encrypt(pad(plaintext.encode(), block_size))
    return ciphertext

def decrypt_text(algorithm, key, block_size, ciphertext, iv):
    cipher = algorithm.new(key, algorithm.MODE_CBC, iv)
    decrypted_data = cipher.decrypt(ciphertext[block_size:])  # Correct offset

    try:
        plaintext = unpad(decrypted_data, block_size)  # Ensure valid padding
    except ValueError:
        print("Decryption failed due to incorrect padding.")
        exit(1)

    return plaintext.decode()

def encrypt_file(algorithm, key,iv, block_size, input_file, output_file, hex_output_file):
    with open(input_file, "rb") as f:
        plaintext = f.read()
    if algorithm == "Twofish":
        ciphertext = encrypt_twofish(plaintext, key, iv)
    else:
        cipher = algorithm.new(key, algorithm.MODE_CBC,iv)
        ciphertext = cipher.iv + cipher.encrypt(pad(plaintext, block_size))
    with open(output_file, "wb") as f:
        f.write(ciphertext)
    save_hex_to_text(ciphertext, hex_output_file)

def decrypt_file(algorithm, key, iv, block_size, input_file, output_file):
    with open(input_file, "rb") as f:
        ciphertext = f.read()
    
    if algorithm == "Twofish":
        plaintext = decrypt_twofish(ciphertext, key, iv)
    else:
        cipher = algorithm.new(key, algorithm.MODE_CBC, iv)
        decrypted_data = cipher.decrypt(ciphertext[block_size:])  # Decrypt only data

        try:
            plaintext = unpad(decrypted_data, block_size)  # Ensure valid padding
        except ValueError as e:
            print(f" Padding error during decryption: {e}")
            print("Possible causes: incorrect key/IV, wrong file format, or corruption.")
            exit(1)

    with open(output_file, "wb") as f:  
        f.write(plaintext)
