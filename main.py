from Crypto.Cipher import AES, Blowfish, DES3
from utility import *
from Advance import advance
from Simple import simple
from validation_key_iv import *


def main():
	print("Choose an operation:")
	print("1. Encrypt")
	print("2. Decrypt")
	operation = input("Enter your choice (1/2): ")

	if operation == "1":
		print("Choose encryption mode:")
		print("1. Simple (Random Key & IV)")
		print("2. Advanced (User-defined Key & IV)")
		encryption_mode = input("Enter your choice (1/2): ")
	else:
		encryption_mode ="2"
	print("Choose data type:")
	print("1. Simple text")
	print("2. File (txt, pdf, ppt, jpg, mp4)")
	type_of_data = input("Enter your choice (1/2): ")


	algorithms = {"1": AES, "2": Blowfish, "3": DES3, "4": "Twofish"}
	print("Choose an encryption algorithm:")
	print("1. AES")
	print("2. Blowfish")
	print("3. 3DES")
	print("4. Twofish")

	choice = input("Enter your choice (1/2/3/4): ")
	if choice not in algorithms:
		print("Invalid choice.")
		return

	algorithm = algorithms[choice]
	if algorithm == AES:
	    print("AES requires a key size of 16 bytes (AES-128), 24 bytes (AES-192), or 32 bytes (AES-256) and block size 16 bytes.")
	elif algorithm == Blowfish:
	    print("Blowfish requires a key size between 4 and 56 bytes and block size of 8 bytes.")
	elif algorithm == DES3:
	    print("3DES requires a key size of 16 bytes or 24 bytes and a block size of 8 bytes.")
	elif algorithm == "Twofish":
	    print("Twofish requires a key size of 16 bytes, 24 bytes or 32 bytes and a block size of 16 bytes.")
	key_size = int(input("Enter key size in bytes: "))
	block_size = int(input("Enter block size in bytes: "))
	if not validate_key_and_block_size(algorithm, key_size, block_size):
		return
	key, iv = get_user_key_iv(encryption_mode, key_size, block_size)
	if encryption_mode=="1":
		simple(operation,type_of_data,algorithm,key,block_size,iv)
	elif encryption_mode=="2":
		advance(operation,type_of_data,algorithm,key,block_size,iv)
	else:
		return
	
if __name__ == "__main__":
    main()

