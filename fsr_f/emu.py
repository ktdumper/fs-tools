from unicorn import *
from unicorn.arm_const import *
import os
import struct
import sys


SEPARATION_SLC = 0
SEPARATION_FLEX = 2
SLC_PAGES_PER_BLOCK = 64
MLC_PAGES_PER_BLOCK = 128

BOOTLOADER_ADDRESES = {
    "C_D1_006 2010/08/18": {
        "FSR_STL_Init": [0x60C090A0, 0x9C],
        "FSR_STL_Open": [0x60C092EC, 0x414],
        "FSR_STL_Read": [0x60C098F8, 0x130],
        "printf_end": 0x60C14930,
        "printf_result": 0x61A46E30,
    },
    "C_D1_001 2011/02/09": {
        "FSR_STL_Init": [0x60C09294, 0x9C],
        "FSR_STL_Open": [0x60C094DC, 0x434],
        "FSR_STL_Read": [0x60C09B48, 0x13C],
        "printf_end": 0x60C1510C,
        "printf_result": 0x61A46E48,
    },
}


def envflag_set(flag):
    return flag in os.environ and os.environ[flag]


def abort(uc):
    print_regs(uc)
    print("!!! ABORT !!!")
    os._exit(-1)


class OnenandFlash:
    def __init__(self, onenand, image_path):
        self.onenand = onenand
        self.onenand_bin = open(image_path + ".bin", "rb")
        self.onenand_oob = open(image_path + ".oob", "rb")
        if image_path.endswith("_mlc"):
            self.pages_per_block = MLC_PAGES_PER_BLOCK
        else:
            self.pages_per_block = SLC_PAGES_PER_BLOCK

        self.size = self.onenand_bin.seek(0, os.SEEK_END)
        self.blocks = self.size // (self.pages_per_block * self.onenand.page_size)

    def read_page(self, uc, block, page_in_block):
        off = (
            block * self.pages_per_block + page_in_block
        ) * self.onenand.page_size
        assert off < self.size
        assert off + self.onenand.page_size < self.size
        # print("-- flash offset 0x{:X}".format(off))
        self.onenand_bin.seek(off)
        self.onenand.dataram = bytearray(self.onenand_bin.read(self.onenand.page_size))
        self.onenand_oob.seek(off // 512 * 16)
        self.onenand.spareram = bytearray(self.onenand_oob.read(self.onenand.spare_size))


class Onenand:
    def __init__(self):
        self.debug = envflag_set("DEBUG_NAND")
        self.debug_trace = self.debug and os.environ["DEBUG_NAND"].lower() == "trace"
        self.int_reads = 0

        self.onenand_mlc = None
        self.onenand_slc = None

        self.syscfg1 = 0xE6C4
        self.mid = 0xEC
        self.did = 0x00
        self.vid = 0x41

        self.page_size = 4096
        self.spare_size = 128

        self.start_addr_1 = 0
        self.start_addr_2 = 0
        self.start_addr_8 = 0

        self.start_buf_reg = 0

        self.pi_mode = False
        self.partition_information = bytearray(b"\xFF" * self.page_size * SLC_PAGES_PER_BLOCK)
        self.int = 0
        self.dataram = bytearray(self.page_size)
        self.spareram = bytearray(self.spare_size)

        self.override_page = dict()
        self.override_spare = dict()

    def _open_image(self, image_path):
        if not os.path.exists(image_path + ".bin"):
            self.print_debug("Image not found: '{:}.bin'".format(image_path))
            return
        if image_path.endswith("_mlc"):
            self.print_debug("MLC image: '{:}.bin'".format(image_path))
            self.onenand_mlc = OnenandFlash(self, image_path)
        else:
            # both onenand_slc and onenand fall here
            self.print_debug("SLC image: '{:}.bin'".format(image_path))
            self.onenand_slc = OnenandFlash(self, image_path)

    def _get_boundary_address(self):
        # Return the configured boundary block where SLC ends 
        # 0 means only 1'st block is SLC and rest is MLC
        return struct.unpack_from("<H", self.partition_information, 0)[0] & 0xFFF

    def open(self, image_path):
        if image_path.endswith("_slc") or image_path.endswith("_mlc"):
            image_path_base = image_path.removesuffix("slc").removesuffix("mlc")
            image_path_slc = image_path_base + "slc"
            image_path_mlc = image_path_base + "mlc"

            self._open_image(image_path_slc)
            self._open_image(image_path_mlc)

            if self.onenand_slc and self.onenand_mlc:
                # This is a FlexNand dump
                self.did |= SEPARATION_FLEX << 8
        else:
            # SLC
            self._open_image(image_path)

        total_size = 0
        separation = (self.did >> 8) & 0b11
        if self.onenand_slc and self.onenand_mlc:
            assert separation == SEPARATION_FLEX
            separation_str = "Flex-OneNAND"
            total_size = self.onenand_slc.size + self.onenand_mlc.size
            # I assume this is for PI
            total_size += SLC_PAGES_PER_BLOCK * self.page_size
        elif self.onenand_slc:
            assert separation == SEPARATION_SLC
            separation_str = "SLC"
            total_size = self.onenand_slc.size
        elif self.onenand_mlc:
            print("Currently unimplemented OneNand configuration (MLC)")
            os._exit(-1)
        else:
            print("No image loaded?")
            os._exit(-1)

        # Guess density bits value
        # (the formula was revelated to me after having 5h of sleep and 12h train trip the previous day)
        if 0 == total_size:
            print("Total NAND size is 0!")
            os._exit(-1)
        if (total_size & (total_size-1)) != 0:
            print("Total NAND size '{}' is not power of 2!".format(total_size))
            os._exit(-1)
        density = 0
        while total_size != (1 << density + 4) << 20:
            density += 1
            if density > 0xF:
                print("Total NAND size '{}' doesn't match any expected size".format(total_size))
                os._exit(-1)
        self.did |= (density & 0xF) << 4

        self.print_debug("DeviceID: {:04X}".format(self.did))
        self.print_debug("* DeviceID [1:0]  Vcc:           {:0b}".format(self.did & 0b11))
        self.print_debug("* DeviceID [2]    Muxed/Demuxed: {:0b}".format((self.did >> 2) & 0b1))
        self.print_debug("* DeviceID [3]    Single/DDP:    {:0b}".format((self.did >> 3) & 0b1))
        self.print_debug("* DeviceID [7:4]  Density:       {:04b} = {}".format((self.did >> 4) & 0xF, total_size))
        self.print_debug("* DeviceID [9:8]  Separation:    {:02b} = {}".format(separation, separation_str))

        if self.onenand_slc and self.onenand_mlc:
            assert 0 < self.onenand_slc.blocks
            # Program the alloc word with the boundary of SLC / MLC
            alloc = self.onenand_slc.blocks - 1
            if 0xFFFF < alloc:
                self.print_debug("Warning: Alloc value beyond max! wrong files? 0x{:04X}", alloc)
                alloc = 0xFFFF
            struct.pack_into("<H", self.partition_information, 0, alloc)

        self.print_debug("* Boundary block: 0x{:04X}".format(self._get_boundary_address()))

    def print_debug(self, *args, **kwargs):
        if self.debug:
            print(*args, **kwargs)

    def _read(self, uc):
        if self.start_buf_reg != 0x800:
            abort(uc)
        if self.start_addr_8 & 0b11 != 0:
            abort(uc)
        if self.start_addr_2 != 0:
            abort(uc)

        page_in_block = self.start_addr_8 >> 2

        if self.pi_mode:
            # Partition Information only has a single SLC block with no ECC
            if self.start_addr_1 != 0:
                print("Tried to access non 0 block while in PI mode")
                abort(uc)
            if (self.syscfg1 & 0x100) == 0:
                print("PI access must have ECC off")
                abort(uc)
            off = self.page_size * page_in_block
            self.dataram = bytearray(
                self.partition_information[off : off + self.page_size]
            )
        elif (self.start_addr_1, self.start_addr_8) in self.override_page:
            self.dataram = bytearray(
                self.override_page[(self.start_addr_1, page_in_block)]
            )
            self.spareram = bytearray(
                self.override_spare[(self.start_addr_1, page_in_block)]
            )
        elif self.onenand_slc:
            slc_blocks = self.onenand_slc.blocks
            if self.onenand_mlc and slc_blocks <= self.start_addr_1:
                block = self.start_addr_1 - slc_blocks
                self.onenand_mlc.read_page(uc, block, page_in_block)
            else:
                self.onenand_slc.read_page(uc, self.start_addr_1, page_in_block)

    def read_reg(self, uc, offset, size):
        if self.debug_trace and (offset < 0x404 or 0x1400 < offset):
            self.print_debug("onenand_read 0x{:X} 0x{:X}".format(offset, size))

        if offset == 0x1E000:
            return self.mid
        elif offset == 0x1E002:
            return self.did
        elif offset == 0x1E004:
            return self.vid
        elif offset == 0x1E442:
            return self.syscfg1
        elif offset == 0x1E482:
            self.int_reads += 1
            if self.int_reads > 100:
                # Pretend its busy until we set flag if its reading INT constantly
                # This seems to be required as in FlexNAND mode the bootloader waits
                # for a while unless its set
                self.int |= 0x8000
            return self.int
        elif size == 4 and offset >= 0x400 and offset < 0x1400:
            return struct.unpack_from("<I", self.dataram[offset - 0x400 :])[0]
        elif size == 2 and offset >= 0x400 and offset < 0x1400:
            return struct.unpack_from("<H", self.dataram[offset - 0x400 :])[0]
        elif size == 4 and offset >= 0x10020 and offset < 0x100A0:
            return struct.unpack_from("<I", self.spareram[offset - 0x10020 :])[0]
        elif size == 2 and offset >= 0x10020 and offset < 0x100A0:
            return struct.unpack_from("<H", self.spareram[offset - 0x10020 :])[0]
        elif offset in [0x1E480, 0x1FE06, 0x1FE04, 0x1FE02, 0x1FE00]:
            return 0
        elif offset == 0x1E49C:
            return 0b100
        else:
            print("onenand_read UNKNOWN offset=0x{:X} size=0x{:X}".format(offset, size))
            abort(uc)

    def write_reg(self, uc, offset, size, value):
        if self.debug_trace and (offset < 0x404 or 0x1400 < offset):
            self.print_debug("onenand_write 0x{:X} 0x{:X} 0x{:X}".format(offset, size, value))

        if offset == 0x1E200:
            self.start_addr_1 = value
        elif offset == 0x1E202:
            self.start_addr_2 = value
        elif offset == 0x1E20E:
            self.start_addr_8 = value
        elif offset == 0x1E400:
            self.start_buf_reg = value
        elif offset == 0x1E442:
            self.print_debug("OneNAND SysCfg1: 0x{:04X} -> 0x{:04X}".format(self.syscfg1, value))
            self.syscfg1 = value
        elif offset == 0x1E498:
            pass
        elif offset == 0x1E440:
            # print("==> OneNAND CMD 0x{:X}".format(value))
            self.int = 0
            self.int_reads = 0

            if value == 0x65:
                self.print_debug("OneNAND CMD: OTP read")
                self.int = 0x8000
            elif value == 0x66:
                self.print_debug("OneNAND CMD: PI mode")
                self.pi_mode = True
                self.int = 0x8000
            elif value == 0x00 or value == 0x03:
                self.print_debug("OneNAND CMD: Read A1 0x{:X}, A2 0x{:X}, A8 0x{:X})".format(
                    self.start_addr_1, self.start_addr_2, self.start_addr_8
                ))
                self._read(uc)
                # read completed
                self.int = 0x8080
            elif value == 0xF0:
                self.print_debug("OneNAND CMD: Reset flash core")
                if self.pi_mode:
                    self.print_debug("Leaving PI mode")
                    self.pi_mode = False
                self.int = 0x8010
            elif value == 0x23:
                self.print_debug("OneNAND CMD: Unlock NAND array a block")
                self.int = 0x8004
            elif value == 0x94:
                # Erase block
                self.print_debug("OneNAND CMD: Erase block 0x{:X}".format(self.start_addr_1))
                if self.pi_mode:
                    self.partition_information = bytearray(b"\xff" * self.page_size)
                else:
                    # Use MLC amount since is bigger
                    for x in range(MLC_PAGES_PER_BLOCK):
                        self.override_page[(self.start_addr_1, x)] = b"\xFF" * self.page_size
                        self.override_spare[(self.start_addr_1, x)] = b"\xFF" * self.spare_size
                self.int = 0xFFFF
            elif value == 0x80:
                # Program page
                page_in_block = self.start_addr_8 >> 2
                self.print_debug("OneNAND CMD: Program page 0x{:X}:0x{:X}".format(
                    self.start_addr_1, page_in_block
                ))
                assert self.start_addr_8 % 4 == 0
                if self.pi_mode:
                    off = page_in_block * self.page_size
                    self.partition_information = (
                        self.partition_information[:off]
                        + self.dataram
                        + self.partition_information[off + self.page_size :]
                    )
                    assert len(self.partition_information) == (self.page_size * SLC_PAGES_PER_BLOCK)
                else:
                    self.override_page[(self.start_addr_1, page_in_block)] = self.dataram
                    self.override_spare[(self.start_addr_1, page_in_block)] = self.spareram
                self.int = 0xFFFF
            else:
                print("onenand_write UNKNOWN CMD REG value=0x{:X}".format(value))
                abort(uc)
        elif offset >= 0x400 and offset < 0x1400:
            bins = value.to_bytes(size, byteorder="little")
            self.dataram[offset - 0x400 : offset - 0x400 + len(bins)] = bins
        elif offset >= 0x10020 and offset < 0x100A0:
            bins = value.to_bytes(size, byteorder="little")
            self.spareram[offset - 0x10020 : offset - 0x10020 + len(bins)] = bins
        else:
            print("onenand_write UNKNOWN offset=0x{:X} size=0x{:X}".format(offset, size))
            abort(uc)


onenand = Onenand()


def onenand_read(uc, offset, size, data):
    # print("onenand read 0x{:08X} size 0x{:X}".format(offset, size))
    return onenand.read_reg(uc, offset, size)


def onenand_write(uc, offset, size, value, data):
    # print("onenand write 0x{:08X} size 0x{:X} data 0x{:X}".format(offset, size, value))
    onenand.write_reg(uc, offset, size, value)


def print_regs(uc):
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
        print(">>> {} : 0x{:08X}".format(name, uc.reg_read(reg)))


def post_print(uc, address, size, user_data):
    data = uc.mem_read(BOOTLOADER_ADDRESES[user_data]["printf_result"], 0x2000)
    data = data[: data.find(b"\x00")]
    print("!! PRINT !! {}".format(data.decode("ascii").rstrip()))


def emu_run_func(uc, bootloader, func):
    funcdata = BOOTLOADER_ADDRESES[bootloader][func]
    uc.emu_start(funcdata[0], funcdata[0] + funcdata[1])


def main():
    if len(sys.argv) < 2:
        print("Please provide nand dump to use")
        os._exit(1)
    if len(sys.argv) < 3:
        sys.argv.append("secondbl.bin")

    with open(sys.argv[2], "rb") as inf:
        bootloader_code = inf.read()

    bootloader = bootloader_code[0x1E0:0x1F3].decode("ascii").replace("\0", " ")
    print("Emulated BL '{:}' string: '{:}'".format(sys.argv[2], bootloader))

    image_path = sys.argv[1].removesuffix(".bin")
    onenand.open(image_path)
    part_path = image_path.removesuffix("_slc").removesuffix("_mlc") + "_part"

    if bootloader not in BOOTLOADER_ADDRESES:
        print("Unknown bootloader provided!")
        os._exit(1)

    for partnum in [0x14, 0x15, 0x19, 0x1A]:
        #print("Partnum => 0x{:X}".format(partnum))
        uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)

        uc.mem_map(0x60C01000, 0x40000)
        uc.mem_write(0x60C01000, bootloader_code)

        uc.reg_write(UC_ARM_REG_SP, 0xE7A91FFC)
        # map stack space
        uc.mem_map(0xE7A90000, 0x2000)

        # bss
        uc.mem_map(0x61100000, 0x950000)

        uc.mem_map(0x70000000, 0x100000)
        info_ptr = 0x70000000 + 0x4000
        buf_ptr = 0x70000000

        # onenand
        uc.mmio_map(0x30000000, 0x20000, onenand_read, None, onenand_write, None)

        # printf
        printf_end = BOOTLOADER_ADDRESES[bootloader]["printf_end"]
        uc.hook_add(
            UC_HOOK_CODE,
            post_print,
            begin=printf_end,
            end=printf_end,
            user_data=bootloader,
        )

        # uc.hook_add(UC_HOOK_CODE, hook_code)

        try:
            # FSR_STL_Init
            emu_run_func(uc, bootloader, "FSR_STL_Init")
            result = uc.reg_read(UC_ARM_REG_R0)
            print("FSR_STL_Init => 0x{:X}".format(result))
            if result != 0:
                break

            uc.reg_write(UC_ARM_REG_R0, 0)
            uc.reg_write(UC_ARM_REG_R1, partnum)
            uc.reg_write(UC_ARM_REG_R2, info_ptr)
            uc.reg_write(UC_ARM_REG_R3, 0)
            emu_run_func(uc, bootloader, "FSR_STL_Open")
            result = uc.reg_read(UC_ARM_REG_R0)
            print("FSR_STL_Open => 0x{:X}".format(result))
            if result != 0:
                if result == 0x80030002:
                    # Unknown partnum
                    continue
                else:
                    break

            print("Read start")

            with open("{}_{:X}.bin".format(part_path, partnum), "wb") as outf:
                blk = 0
                while True:
                    uc.reg_write(UC_ARM_REG_SP, 0x70010000)

                    uc.reg_write(UC_ARM_REG_R0, 0)
                    uc.reg_write(UC_ARM_REG_R1, partnum)
                    uc.reg_write(UC_ARM_REG_R2, blk)
                    uc.reg_write(UC_ARM_REG_R3, 1)
                    uc.mem_write(
                        uc.reg_read(UC_ARM_REG_SP), struct.pack("<II", buf_ptr, 0)
                    )
                    if blk % 0x1000 == 0:
                        print("Reading part 0x{:X} block 0x{:X}".format(partnum, blk))
                    emu_run_func(uc, bootloader, "FSR_STL_Read")
                    ret = uc.reg_read(UC_ARM_REG_R0)
                    if ret != 0:
                        print("FSR_STL_Read() => 0x{:X}".format(ret))

                    if ret == 0x80030000:
                        break
                    elif ret != 0:
                        raise RuntimeError("Unexpected result")

                    data = uc.mem_read(buf_ptr, 512)
                    outf.write(data)
                    blk += 1
                if blk == 0:
                    raise RuntimeError("No block was read")
        except unicorn.UcError:
            print_regs(uc)
            raise
        except:
            raise


if __name__ == "__main__":
    main()

# sp = E7A91FFC
