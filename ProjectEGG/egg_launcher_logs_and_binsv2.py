def reverse_bit_flipping(input_bytes):
    # Reverse bit flipping: Apply bitwise NOT (~) to each byte in the input
    return bytes([~b & 0xFF for b in input_bytes])

def read_and_reverse_bitflip_to_file():
    with open("data.bin", "rb") as log_file:  # Open the file in binary mode
        flipped_data = log_file.readlines()

        # Open the output file to write the decrypted data
        with open("dec.txt", "w", encoding="shift-jis") as output_file:
            for index, line in enumerate(flipped_data):
                # Reverse bit flip on the raw byte data (line.strip() removes the newline at the end)
                original_bytes = reverse_bit_flipping(line.strip())

                # Now decode the reversed bytes as Shift-JIS
                try:
                    # Convert the bytes to a Shift-JIS string
                    shift_jis_data = original_bytes.decode('shift-jis')
                    
                    # Write the decrypted Shift-JIS data to the output file
                    output_file.write(shift_jis_data)

                except UnicodeDecodeError as e:
                    print(f"Error decoding Shift-JIS for line {index + 1}: {e}")

    print("Decrypted data has been written to 'dec.txt'.")

# Step 2: Read the data back and reverse the bit flip, writing the results to a new file
read_and_reverse_bitflip_to_file()
