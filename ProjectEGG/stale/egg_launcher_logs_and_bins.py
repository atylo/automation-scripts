def reverse_bit_flipping(input_bytes):
    # Reverse bit-flipping: Apply bitwise NOT (~) to each byte in the input
    return bytes([~b & 0xFF for b in input_bytes])

def read_and_reverse_bitflip():
    with open("ln.log", "rb") as log_file:  # Open the file in binary mode
        flipped_data = log_file.readlines()

        for index, line in enumerate(flipped_data):
            # Reverse bit flip on the raw byte data
            original_bytes = reverse_bit_flipping(line.strip())

            # Now decode the reversed bytes as Shift-JIS
            try:
                # Convert the bytes to a Shift-JIS string
                shift_jis_data = original_bytes.decode('shift-jis')
                # Display original (decrypted) text in Shift-JIS encoding
                print(f"Original (Decrypted) Data from line {index + 1}: {shift_jis_data}")
            except UnicodeDecodeError as e:
                print(f"Error decoding Shift-JIS for line {index + 1}: {e}")

# Step 2: Read the data back and reverse the bit flip, displaying the results
read_and_reverse_bitflip()
