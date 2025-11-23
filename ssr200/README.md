# SSR200

## Environment
Download this script.
https://github.com/irdkwia/various-keitai-assemble/blob/main/assemble_ssr200.py

## Usage
The file `nand.oob` must also be placed in the same folder.

```
python3 assemble_ssr200.py nand.bin nand_remapped.bin
python3 carve_nec_fat.py nand_remapped.bin fat_dir

// For the P2102V model, add the "--disable-normalize" option.
python3 convert_fat.py fat_dir converted_fat_dir
```

## NEC-Customized FAT
FAT file systems with a `BS_VolLab` of `NECVOL` may be customized by NEC.
They can be converted to a standard FAT format using convert_fat.py, but they have the following characteristics:

- In the FAT area, a 16-byte information header, which appears to be a checksum, is inserted every 512 bytes.
- Backup directory clusters are retained. These clusters are arranged alternately as follows:
`CURRENT CLUSTER 1 → OLD CLUSTER 1 → CURRENT CLUSTER 2 → OLD CLUSTER 2 → CURRENT CLUSTER 3 → OLD CLUSTER 3`
- In some cases, proprietary parameters are inserted into the directory structure.