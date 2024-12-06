import sys
import os

def main(input_path, output_dir):
    os.makedirs(output_dir, exist_ok=True)

    with open(input_path, "rb") as file:
        binary = file.read()
        
    output_offsets = []
    binary_len = len(binary)
    
    for offset in range(0, binary_len-0x10, 0x10):
        if binary[offset+3:offset+3+8] != b"MSDOS5.0": continue
        output_offsets.append(offset)
        print(f"FAT found: {hex(offset)}")
    
    if len(output_offsets) == 0:
        raise Exception("not found!")
        
    output_offsets.append(binary_len)
    
    for i in range(len(output_offsets)-1):
        output_path = os.path.join(output_dir, f"fat_{output_offsets[i]:08X}.bin")
        with open(output_path, "wb") as output:
            output.write(binary[output_offsets[i]:output_offsets[i+1]])


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])