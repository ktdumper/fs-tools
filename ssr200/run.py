import sys
import os
import glob
import re
import convert_ssr200
import extract
import carve_msdos50_fat

if __name__ == "__main__":
    nand_path = sys.argv[1]
    in_dir = os.path.dirname(sys.argv[1])
    out_dir = os.path.join(in_dir, "Extracted_FAT")

    print("\nStart remapping the NAND.")
    oob_path = re.sub(r"\.bin$", ".oob", sys.argv[1])
    remapped_nand_path = sys.argv[1] + "_remapped.bin"
    convert_ssr200.main(nand_path, oob_path, remapped_nand_path)
    print(f"Success!: {remapped_nand_path}")

    print("\nStart carving FATs. (MSDOS5.0)")
    carve_msdos50_fat.main(remapped_nand_path, out_dir)

    print("\nStart extracting FATs.")
    for path in glob.glob(os.path.join(glob.escape(out_dir), "*.bin")):
        dir_name = re.sub(r"\.bin$", "",os.path.basename(path))
        extract.extractfat(path, os.path.join(out_dir, dir_name))
        
    print(f"\nProcessing completed!")
    print(f"Output => {out_dir}")
