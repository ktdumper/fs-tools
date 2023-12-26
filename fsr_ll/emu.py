import os
from qiling import Qiling
import struct


def abort():
    print("!! runtime abort !!")
    os._exit(-1)


onenand_bin = open("onenand.bin", "rb")
onenand_oob = open("onenand.oob", "rb")


class Onenand:

    def __init__(self):
        self.mid = 0xEC
        self.did = 0x60
        self.vid = 0x31
        self.syscfg1 = 0xE6C4

        self.start_addr_1 = 0
        self.start_addr_2 = 0
        self.start_addr_8 = 0

        self.start_buf_reg = 0

        self.int = 0
        self.dataram = bytearray(0x1000)
        self.spareram = bytearray(128)

    def _read(self):
        # regular read
        print("!!! read(0x{:X}, 0x{:X}, 0x{:X})".format(self.start_addr_1, self.start_addr_2, self.start_addr_8))

        if self.start_buf_reg != 0x800:
            abort()
        if self.start_addr_8 & 0b11 != 0:
            abort()
        if self.start_addr_2 != 0:
            abort()

        off = self.start_addr_1 * 64 * 4096 + (self.start_addr_8 >> 2) * 4096
        print("-- flash offset 0x{:X}".format(off))
        onenand_bin.seek(off)
        self.dataram = onenand_bin.read(4096)
        onenand_oob.seek(off // 512 * 16)
        self.spareram = onenand_oob.read(128)

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
            print("==> OneNAND CMD 0x{:X}".format(value))
            self.int = 0

            if value == 0x65:
                # OTP read
                self.int = 0x8000
            elif value == 0x00:
                self._read()

                # read completed
                self.int = 0x8080
            elif value == 0xF0:
                # reset flash core
                self.int = 0x8010
            elif value == 0x23:
                # Unlock NAND array a block
                self.int = 0x8004
            else:
                abort()
        else:
            abort()


onenand = Onenand()


if __name__ == "__main__":
    ql = Qiling([r'main'], "arm-linux-gnueabi")

    def cb_read(ql, offset, size):
        return onenand.read_reg(offset, size)

    def cb_write(ql, offset, size, value):
        onenand.write_reg(offset, size, value)

    ql.mem.map_mmio(0xfc600000, 0x20000, cb_read, cb_write)

    ql.run()
