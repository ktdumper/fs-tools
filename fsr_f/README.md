# fsr_f

FSR emulator based on Fujitsu phone bootloader.

## Environment

```
pip3 install unicorn
```

## Usage

Pass path of dump's onenand.bin, onenand_slc.bin or onenand_mlc.bin as first arg

Optional second arg can be provided for using a different bootloader (addresses may be needed to be added)

Extracted partitions will be saved in the same folder as the dump file with _part_XX appended

```
python3 emu.py path/to/onenand.bin
```

