from unicorn import *
from unicorn.arm_const import *
import os
import struct
import sys


def abort():
    print_regs()
    os._exit(-1)


mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)

onenand_bin = open("onenand.bin", "rb")
onenand_oob = open("onenand.oob", "rb")


class Onenand:

    def __init__(self):
        self.mid = 0xEC
        self.did = 0x50
        self.vid = 0x41
        self.syscfg1 = 0xE6C4

        # setup for SLC
        self.pages_per_block = 64
        self.page_size = 4096
        self.spare_size = 128

        self.start_addr_1 = 0
        self.start_addr_2 = 0
        self.start_addr_8 = 0

        self.start_buf_reg = 0

        self.int = 0
        self.dataram = bytearray(self.page_size)
        self.spareram = bytearray(self.spare_size)

        self.override_page = dict()
        self.override_spare = dict()

    def _read(self):
        # regular read
        # print("!!! read(0x{:X}, 0x{:X}, 0x{:X})".format(self.start_addr_1, self.start_addr_2, self.start_addr_8))

        if self.start_buf_reg != 0x800:
            abort()
        if self.start_addr_8 & 0b11 != 0:
            abort()
        if self.start_addr_2 != 0:
            abort()

        page_in_block = self.start_addr_8 >> 2
        if (self.start_addr_1, self.start_addr_8) in self.override_page:
            self.dataram = bytearray(self.override_page[(self.start_addr_1, page_in_block)])
            self.spareram = bytearray(self.override_spare[(self.start_addr_1, page_in_block)])
        else:
            off = (self.start_addr_1 * self.pages_per_block + page_in_block) * self.page_size
            # print("-- flash offset 0x{:X}".format(off))
            onenand_bin.seek(off)
            self.dataram = bytearray(onenand_bin.read(self.page_size))
            onenand_oob.seek(off // 512 * 16)
            self.spareram = bytearray(onenand_oob.read(self.spare_size))

    def read_reg(self, offset, size):
        # if offset >= 0x404 and offset < 0x1400:
        #     print(".", end="")
        # else:
        #     print("onenand_read 0x{:X} 0x{:X}".format(offset, size))

        if offset == 0x1E000:
            return self.mid
        elif offset == 0x1E002:
            return self.did
        elif offset == 0x1E004:
            return self.vid
        elif offset == 0x1E442:
            return self.syscfg1
        elif offset == 0x1E482:
            return self.int
        elif size == 4 and offset >= 0x400 and offset < 0x1400:
            return struct.unpack_from("<I", self.dataram[offset-0x400:])[0]
        elif size == 4 and offset >= 0x10020 and offset < 0x100A0:
            return struct.unpack_from("<I", self.spareram[offset-0x10020:])[0]
        elif size == 2 and offset >= 0x10020 and offset < 0x100A0:
            return struct.unpack_from("<H", self.spareram[offset-0x10020:])[0]
        elif offset in [0x1E480, 0x1FE06, 0x1FE04, 0x1FE02, 0x1FE00]:
            return 0
        elif offset == 0x1E49C:
            return 0b100
        else:
            abort()

    def write_reg(self, offset, size, value):
        # print("onenand_write 0x{:X} 0x{:X} 0x{:X}".format(offset, size, value))

        if offset == 0x1E200:
            self.start_addr_1 = value
        elif offset == 0x1E202:
            self.start_addr_2 = value
        elif offset == 0x1E20E:
            self.start_addr_8 = value
        elif offset == 0x1E400:
            self.start_buf_reg = value
        elif offset == 0x1E442:
            self.syscfg1 = value
        elif offset == 0x1E498:
            pass
        elif offset == 0x1E440:
            # print("==> OneNAND CMD 0x{:X}".format(value))
            self.int = 0

            if value == 0x65:
                # OTP read
                self.int = 0x8000
            elif value == 0x00 or value == 0x03:
                self._read()

                # read completed
                self.int = 0x8080
            elif value == 0xF0:
                # reset flash core
                self.int = 0x8010
            elif value == 0x23:
                # Unlock NAND array a block
                self.int = 0x8004
            elif value == 0x94:
                # Erase block
                print("=> Erase block 0x{:X}".format(self.start_addr_1))
                for x in range(self.pages_per_block):
                    self.override_page[(self.start_addr_1, x)] = b"\xFF" * self.page_size
                    self.override_spare[(self.start_addr_1, x)] = b"\xFF" * self.spare_size
                self.int = 0xFFFF
            elif value == 0x80:
                # Program page
                assert self.start_addr_8 % 4 == 0
                page_in_block = self.start_addr_8 // 4
                print("=> Program page 0x{:X}:0x{:X}".format(self.start_addr_1, page_in_block))
                self.override_page[(self.start_addr_1, page_in_block)] = self.dataram
                self.override_spare[(self.start_addr_1, page_in_block)] = self.spareram
                self.int = 0xFFFF
            else:
                print("UNKNOWN CMD REG value=0x{:X}".format(offset, value))
                abort()
        elif offset >= 0x400 and offset < 0x1400:
            bins = value.to_bytes(size, byteorder="little")
            self.dataram[offset-0x400:offset-0x400+len(bins)] = bins
        elif offset >= 0x10020 and offset < 0x100A0:
            bins = value.to_bytes(size, byteorder="little")
            self.spareram[offset-0x10020:offset-0x10020+len(bins)] = bins
        else:
            print("UNKNOWN offset=0x{:X} size=0x{:X}".format(offset, size))
            abort()


onenand = Onenand()


def onenand_read(uc, offset, size, data):
    # print("onenand read 0x{:08X} size 0x{:X}".format(offset, size))
    return onenand.read_reg(offset, size)


def onenand_write(uc, offset, size, value, data):
    # print("onenand write 0x{:08X} size 0x{:X} data 0x{:X}".format(offset, size, value))
    onenand.write_reg(offset, size, value)


def print_regs():
    regs = [
        ("r0", UC_ARM_REG_R0),
        ("r1", UC_ARM_REG_R1),
        ("r2", UC_ARM_REG_R2),
        ("r3", UC_ARM_REG_R3),
        ("r4", UC_ARM_REG_R4),
        ("r5", UC_ARM_REG_R5),
        ("r6", UC_ARM_REG_R6),
        ("r7", UC_ARM_REG_R7),
        ("r8", UC_ARM_REG_R8),
        ("r9", UC_ARM_REG_R9),
        ("r10", UC_ARM_REG_R10),
        ("r11", UC_ARM_REG_R11),
        ("r12", UC_ARM_REG_R12),
        ("lr", UC_ARM_REG_LR),
        ("pc", UC_ARM_REG_PC),
        ("sp", UC_ARM_REG_SP),
    ]

    for name, reg in regs:
        print(">>> {} : 0x{:08X}".format(name, mu.reg_read(reg)))


def post_print(uc, address, size, user_data):
    data = mu.mem_read(0x61a46e48, 0x2000)
    data = data[:data.find(b"\x00")]
    print("!! PRINT !! {}".format(data.decode("ascii").rstrip()))


def main():
    with open("secondbl.bin", "rb") as inf:
        code = inf.read()

    mu.mem_map(0x60c01000, 0x40000)
    mu.mem_write(0x60c01000, code)

    mu.reg_write(UC_ARM_REG_SP, 0xE7A91FFC)
    # map stack space
    mu.mem_map(0xE7A90000, 0x2000)

    # bss
    mu.mem_map(0x61100000, 0x950000)

    mu.mem_map(0x70000000, 0x100000)
    info_ptr = 0x70000000 + 0x4000
    buf_ptr = 0x70000000

    # onenand
    mu.mmio_map(0x30000000, 0x20000, onenand_read, None, onenand_write, None)

    mu.hook_add(UC_HOOK_CODE, post_print, begin=0x60c2fbec, end=0x60c2fbec)

    # mu.hook_add(UC_HOOK_CODE, hook_code)

    try:
        partnum = int(sys.argv[1], 16)

        # FSR_STL_Init
        mu.emu_start(0x60c09294, 0x60c09330)
        if mu.reg_read(UC_ARM_REG_R0) != 0:
            raise RuntimeError("FSR_STL_Init")

        mu.reg_write(UC_ARM_REG_R0, 0)
        mu.reg_write(UC_ARM_REG_R1, partnum)
        mu.reg_write(UC_ARM_REG_R2, info_ptr)
        mu.reg_write(UC_ARM_REG_R3, 0)
        mu.emu_start(0x60c094dc, 0x60c09910)
        if mu.reg_read(UC_ARM_REG_R0) != 0:
            raise RuntimeError("FSR_STL_Open")

        print("read start")

        with open(sys.argv[2], "wb") as outf:
            for blk in range(2 ** 32):
                mu.reg_write(UC_ARM_REG_SP, 0x70010000)

                mu.reg_write(UC_ARM_REG_R0, 0)
                mu.reg_write(UC_ARM_REG_R1, partnum)
                mu.reg_write(UC_ARM_REG_R2, blk)
                mu.reg_write(UC_ARM_REG_R3, 1)
                mu.mem_write(mu.reg_read(UC_ARM_REG_SP), struct.pack("<II", buf_ptr, 0))
                print("read 0x{:X}".format(blk))
                mu.emu_start(0x60c09b48, 0x60c09c84)
                ret = mu.reg_read(UC_ARM_REG_R0)
                print("FSR_STL_Read() => {}".format(ret))

                if ret != 0:
                    break

                data = mu.mem_read(buf_ptr, 512)
                outf.write(data)
    except unicorn.UcError:
        print_regs()
        raise

if __name__ == "__main__":
    main()

# sp = E7A91FFC
