from Crypto.Cipher import AES, Blowfish, DES3
from Crypto.Random import get_random_bytes

def get_user_key_iv(mode, key_size, block_size):
    if mode == "1":
        return get_random_bytes(key_size), get_random_bytes(block_size)
    else:
        try:
            key = bytes.fromhex(input(f"Enter key ({key_size} bytes in hex): ").strip())
            iv = bytes.fromhex(input(f"Enter IV ({block_size} bytes in hex): ").strip())
            
            if len(key) != key_size or len(iv) != block_size:
                raise ValueError("Error: Incorrect key or IV length.")
            
            return key, iv
        except ValueError as e:
            print(f"Error: Invalid key or IV. Ensure correct hex format.")
            print(f"Exception: {e}")
            exit(1)
            
def validate_key_and_block_size(algorithm, key, block_size):
    try:
        if algorithm == AES:
            
            valid_key_sizes = [16, 24, 32]
            if key not in valid_key_sizes or block_size != 16:
                raise ValueError("Invalid AES key or block size.")
        
        elif algorithm == Blowfish:
            
            if not (4 <= key <= 56) or block_size != 8:
                raise ValueError("Invalid Blowfish key or block size.")
        
        elif algorithm == DES3:
            
            if key not in [16, 24] or block_size != 8:
                raise ValueError("Invalid 3DES key or block size.")
        
        elif algorithm == "Twofish":
            
            if key not in [16, 24, 32] or block_size != 16:
                raise ValueError("Invalid Twofish key or block size.")
        
        else:
            raise ValueError("Unsupported algorithm.")

    except ValueError as e:
        print(e)
        return False

    return True

