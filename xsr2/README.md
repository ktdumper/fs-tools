# xsr2

## Environment

```
sudo apt install gcc-arm-linux-gnueabi qemu qemu-user-static qemu-system-arm
```

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
