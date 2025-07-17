from twofish import *
from Crypto.Cipher import AES, Blowfish, DES3
from Crypto.Util.Padding import pad, unpad
from utility import *
from twofish import *
import filetype
import os
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

def is_hex_file(file_path):
    """Checks if a file contains only valid hex characters"""
    try:
        with open(file_path, "r") as f:
            content = f.read().strip()
            int(content, 16)  # Try converting to integer (hex check)
            return True
    except (ValueError, FileNotFoundError):
        return False  # Not a valid hex file

def decrypt_and_save(algorithm, key, iv, block_size, input_file):
    """Handles decryption and saves the decrypted file"""
    decrypted_hex_file = f"decrypted_hex_{input_file}.txt"
    final_output_file = f"decrypted_{input_file}"

    decrypt_file(algorithm, key, iv, block_size, input_file, decrypted_hex_file)
    print(f"Decrypted hex stored in: {decrypted_hex_file}")

    convert_from_text(decrypted_hex_file, final_output_file)

    # Auto-detect file type and rename
    kind = filetype.guess(final_output_file)
    if kind is not None:
        new_name = f"{final_output_file}.{kind.extension}"
        os.rename(final_output_file, new_name)
        final_output_file = new_name  # Update final name
    
    print(f"Final decrypted file stored as: {final_output_file}")
    return final_output_file

def decrypt_advanced(algorithm, key, iv, block_size, input_file):
    """Detects whether the file is encrypted in binary or hex format and processes accordingly"""
    
    if is_hex_file(input_file):
        temp_binary_file = f"binary_{input_file[:input_file.rfind('.')]}"
        convert_from_text(input_file, temp_binary_file)
        return decrypt_and_save(algorithm, key, iv, block_size, temp_binary_file)
    
    return decrypt_and_save(algorithm, key, iv, block_size, input_file)


def advance(operation,type_of_data,algorithm,key,block_size,iv):
	if type_of_data == "1":
        
		if operation == "1":
			plaintext = input("Enter text: ")
			ciphertext = encrypt_twofish(plaintext.encode(), key, iv) if algorithm == "Twofish" else encrypt_text(algorithm, key, block_size, plaintext, iv)
			print(f"Encrypted text (hex): {ciphertext.hex()}")
			print(f"Key (hex): {key.hex()}")
			print(f"IV (hex): {iv.hex()}")
		else:
			ciphertext_hex = input("Enter ciphertext in hex: ")
			ciphertext = bytes.fromhex(ciphertext_hex)
			decrypted_text = decrypt_twofish(ciphertext, key, iv).decode() if algorithm == "Twofish" else decrypt_text(algorithm, key, block_size, ciphertext,iv)
			print(f"Decrypted text: {decrypted_text}")
	else:
		if operation == "1":
			input_file = input("Enter the input file path: ")
			hex_file = "hex_" + input_file + ".txt" # Store hex file
			encrypted_file = "encrypted_crpty_" + input_file    # Encrypted file in given format
			last=input_file.rfind('.')
			encrypted_hex_file = "encrypted_hex_" + input_file[:last]+ ".txt" # Encrypted file in hex
			convert_to_text(input_file, hex_file)

			encrypt_file(algorithm, key,iv, block_size, hex_file, encrypted_file, encrypted_hex_file)
			print(f"Encrypted file stored in: {encrypted_file}")
			print(f"Encrypted hex stored in: {encrypted_hex_file}")
			print(f"Key (hex): {key.hex()}")
			print(f"IV (hex): {iv.hex()}")
		else:
			input_file = input("Enter the input file path: ")
			decrypt_advanced(algorithm, key, iv, block_size, input_file)



	
