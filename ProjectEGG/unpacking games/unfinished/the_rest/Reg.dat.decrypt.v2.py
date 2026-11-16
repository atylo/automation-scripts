import struct

def decrypt_csharp_logic(input_bytes, key=9932):
    """
    Exact implementation of C# method: 
    private ValueTuple<byte[], int> A(byte[] A_1, int A_2, int A_3)
    """
    # A_1 is the input buffer
    A_1 = bytearray(input_bytes)
    # A_2 is the length
    A_2 = len(A_1)
    # A_3 is the key
    A_3 = key
    
    # int num = A_2 - 1;
    num = A_2 - 1
    if num <= 0:
        return bytearray()
    
    # byte[] array = new byte[num];
    array = bytearray(num)
    
    # byte b = A_1[Math.Abs(A_3 % num)];
    salt_index = abs(A_3 % num)
    b = A_1[salt_index]
    
    print(f"Decryption Info: Size={A_2}, Key={A_3}, Salt Index={salt_index}, Salt=0x{b:02X}")

    # Main Decryption Loop
    for i in range(A_2):
        # Condition: Before the Salt
        if salt_index > i:
            # array[i] = A_1[i] - b * (byte)(i * i % 3);
            modifier = (i * i) % 3
            val = (A_1[i] - (b * modifier)) & 0xFF
            array[i] = val
            
        # Condition: After the Salt (Note: writes to i-1)
        if salt_index < i:
            # array[i - 1] = (byte)((int)A_1[i] - (int)b * (i * i % 7));
            modifier = (i * i) % 7
            val = (A_1[i] - (b * modifier)) & 0xFF
            array[i - 1] = val
            
    # Bitwise Inversion Loop
    for i in range(num):
        # if (A_3 % 7 == i % 5 || A_3 % 2 == i % 2)
        if (A_3 % 7 == i % 5) or ((A_3 % 2) == (i % 2)):
            array[i] = ~array[i] & 0xFF
            
    return array

# Run the logic
try:
    with open("reg.dat", "rb") as f:
        file_data = f.read()

    decrypted = decrypt_csharp_logic(file_data)

    with open("reg_decrypted.dat", "wb") as f:
        f.write(decrypted)
        
    print("Done.")
except Exception as e:
    print(e)