# fsr_ll

## Environment

```
sudo apt install gcc-arm-linux-gnueabi
pip3 install qiling
```

## Build

```
arm-linux-gnueabi-gcc -static -omain fsr.ko fsr_stl.ko main.c
```

## Usage

First, place `onenand.bin` and `onenand.oob` in this folder.


```
python3 emu.py
```


