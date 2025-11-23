import sys
import os

def main(input_path, output_dir):
    os.makedirs(output_dir, exist_ok=True)

    with open(input_path, "rb") as file:
        image = file.read()
        
    fat_offsets = []
    image_size = len(image)
    
    for offset in range(0, image_size, 0x200):
        if image[offset + 0x2B : offset + 0x36] != b"NECVOL     ":
            continue
        if image[offset + 0x1FE : offset + 0x200] != b"\x55\xAA":
            continue

        fat_offsets.append(offset)
        print(f"FAT found: {hex(offset)}")
    
    if len(fat_offsets) == 0:
        raise Exception("not found!")
        
    fat_offsets.append(image_size)
    
    for i in range(len(fat_offsets)-1):
        output_path = os.path.join(output_dir, f"{i}_FAT_{fat_offsets[i]:08X}.bin")
        with open(output_path, "wb") as output:
            output.write(image[fat_offsets[i] : fat_offsets[i+1]])

if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])