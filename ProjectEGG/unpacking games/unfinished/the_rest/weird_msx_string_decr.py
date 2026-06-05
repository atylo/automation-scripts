import os
import struct
import sys

def decrypt_msx_string(ciphertext: str, key: str = "v0Uw5i2") -> str:

    ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789()_-+*=~^!&$%#[]."
    
    if len(ALPHABET) != 79:
        raise ValueError(f"Alphabet must be exactly 79 characters long. Current length: {len(ALPHABET)}")

    if not ciphertext:
        return ""

    # The last character of the ciphertext is always the trailing checksum character
    cipher_body = ciphertext[:-1]
    expected_checksum_char = ciphertext[-1]

    plaintext_chars = []
    checksum_accumulator = 0
    key_len = len(key)

    # Decode loop
    for i, cipher_char in enumerate(cipher_body):
        # 1. Find the index of the ciphertext character in the custom alphabet
        if cipher_char not in ALPHABET:
            raise ValueError(f"Character '{cipher_char}' not found in custom alphabet.")
        cipher_idx = ALPHABET.index(cipher_char)

        # 2. Get the corresponding key character (mimics the optimized looping index v10)
        key_char = key[i % key_len]

        # 3. Apply the modular shift subtraction formula:
        # P = (C - (K % 79) + 79) % 79
        plain_idx = cipher_idx - (ord(key_char) % 79)
        if plain_idx < 0:
            plain_idx += 79

        # 4. Record the decrypted index for the checksum validation
        checksum_accumulator += plain_idx

        # 5. Translate the index back to the plaintext character
        plaintext_chars.append(ALPHABET[plain_idx])

    # Checksum Validation
    actual_checksum_char = ALPHABET[checksum_accumulator % 79]
    if actual_checksum_char != expected_checksum_char:
        print("[Warning] Checksum validation failed! The decrypted text may be corrupt or the alphabet/key is wrong.")
    else:
        print("[Success] Checksum validation passed.")

    return "".join(plaintext_chars)


# =============================================================================
# EXAMPLE USAGE
# =============================================================================
if __name__ == "__main__":
    # Example encrypted string from your launcher context: "v0Uw5i2" was used 
    # against resource blocks. 
    encrypted_input = "d.Rzm^unVKke!"
    
    try:
        decrypted_text = decrypt_msx_string(encrypted_input)
        print(f"Decrypted Result: {decrypted_text}")
    except ValueError as e:
        print(f"Error: {e}")
