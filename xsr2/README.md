# xsr2

## Build

```
arm-linux-gnueabi-gcc xsr_stl.ko main.c -o main
```

## Usage

```
export QEMU_LD_PREFIX=/usr/arm-linux-gnueabi
./main onenand.bin onenand.oob B output.bin
```

Typically the partition (3rd argument) is either 0xA or 0xB.
