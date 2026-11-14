# fsr_f

FSR emulator based on the bundled Fujitsu phone bootloader. Reconstructs logical
STL partition images from separate `onenand.bin` and `onenand.oob` dumps.

## Environment

```sh
pip3 install unicorn
```

## Usage

```sh
python3 emu.py 17 part_17.bin --nand /path/to/onenand.bin --oob /path/to/onenand.oob
python3 emu.py 1A part_1A.bin --nand /path/to/onenand.bin --oob /path/to/onenand.oob
```

## Profile

| Profile | NAND | OOB | Dies | Blocks per die |
| --- | --- | --- | --- | --- |
| `512M` | 512 MiB | 16 MiB | 1 | 2048 |
| `2G` | 2 GiB | 64 MiB | 2 | 4096 |
