#include <tomcrypt.h>
#include <string.h>

int encrypt_bytes(unsigned char *plaintext, int plaintext_len, unsigned char *key, int key_len, unsigned char *iv, unsigned char *ciphertext) {
    int err, cipher_idx;
    symmetric_CBC cbc;

    cipher_idx = register_cipher(&twofish_desc);
    if (cipher_idx == -1) {
        printf("Error: Twofish cipher registration failed.\n");
        return -1;
    }

    err = cbc_start(cipher_idx, iv, key, key_len, 0, &cbc);
    if (err != CRYPT_OK) {
        printf("Error in cbc_start: %s\n", error_to_string(err));
        return err;
    }

    err = cbc_encrypt(plaintext, ciphertext, plaintext_len, &cbc);
    if (err != CRYPT_OK) {
        printf("Error in cbc_encrypt: %s\n", error_to_string(err));
        cbc_done(&cbc);
        return err;
    }

    cbc_done(&cbc);
    return 0;
}

int decrypt_bytes(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, int key_len, unsigned char *iv, unsigned char *plaintext) {
    int err, cipher_idx;
    symmetric_CBC cbc;

    // Register Twofish cipher
    if ((cipher_idx = register_cipher(&twofish_desc)) == -1) {
        return -1;  // Cipher registration failed
    }

    // Initialize CBC mode
    if ((err = cbc_start(cipher_idx, iv, key, key_len, 0, &cbc)) != CRYPT_OK) {
        return err;  // CBC initialization failed
    }

    // Decrypt the data
    if ((err = cbc_decrypt(ciphertext, plaintext, ciphertext_len, &cbc)) != CRYPT_OK) {
        cbc_done(&cbc);
        return err;  // Decryption failed
    }

    cbc_done(&cbc);
    return 0;  // Success
}

