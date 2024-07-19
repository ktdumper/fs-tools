# fsr_f

FSR emulator based on Fujitsu phone bootloader.

## Environment

```
pip3 install unicorn
```

## Usage

First, place `onenand.bin` and `onenand.oob` in this folder.


```
python3 emu.py 14 part_14.bin
python3 emu.py 15 part_15.bin
python3 emu.py 19 part_19.bin
python3 emu.py 1A part_1A.bin
```

