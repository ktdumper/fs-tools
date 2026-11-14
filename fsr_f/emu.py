from unicorn import *
from unicorn.arm_const import *
import argparse
from dataclasses import dataclass
from pathlib import Path
import struct
import sys
import unicorn


@dataclass(frozen=True)
class Geometry:
    did: int
    dies: int
    blocks_per_die: int

    @property
    def data_size(self):
        return self.dies * self.blocks_per_die * 64 * 4096


PROFILES = {
    "512M": Geometry(0x50, 1, 2048),
    # Compatibility geometry for 2 GiB dual-die dumps, not a measured hardware ID.
    "2G": Geometry(0x68, 2, 4096),
}


def select_geometry(data_size, oob_size, profile="auto"):
    if profile == "auto":
        matches = [name for name, geometry in PROFILES.items()
                   if geometry.data_size == data_size]
        if not matches:
            raise ValueError(f"unsupported NAND size: {data_size} bytes")
        profile = matches[0]
    geometry = PROFILES[profile]
    if data_size != geometry.data_size:
        raise ValueError(f"{profile} expects {geometry.data_size} NAND bytes, got {data_size}")
    if oob_size != data_size // 4096 * 128:
        raise ValueError("OOB size must be 128 bytes per 4096-byte NAND page")
    return profile, geometry


def abort():
    print_regs()
    raise RuntimeError("unsupported OneNAND operation")


mu = None


class Onenand:

    def __init__(self, nand_file, oob_file, geometry):
        self.nand_file = nand_file
        self.oob_file = oob_file
        self.geometry = geometry
        self.mid = 0xEC
        self.did = geometry.did
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

    def physical_block(self):
        die = self.start_addr_1 >> 15
        block = self.start_addr_1 & 0x7FFF
        if self.start_addr_2 not in (0, 0x8000) or (
                self.start_addr_2 == 0x8000 and self.geometry.dies == 1):
            raise ValueError(f"invalid SA2: 0x{self.start_addr_2:X}")
        if die >= self.geometry.dies or block >= self.geometry.blocks_per_die:
            raise ValueError(f"OneNAND block out of range: 0x{self.start_addr_1:X}")
        return die * self.geometry.blocks_per_die + block

    def page_key(self):
        if self.start_addr_8 & 3 or self.start_addr_8 >> 2 >= self.pages_per_block:
            raise ValueError(f"invalid page address: 0x{self.start_addr_8:X}")
        return self.physical_block(), self.start_addr_8 >> 2

    def _read(self):
        if self.start_buf_reg != 0x800:
            raise ValueError(f"unsupported buffer register: 0x{self.start_buf_reg:X}")
        key = self.page_key()
        if key in self.override_page:
            self.dataram = bytearray(self.override_page[key])
            self.spareram = bytearray(self.override_spare[key])
        else:
            page = key[0] * self.pages_per_block + key[1]
            self.nand_file.seek(page * self.page_size)
            self.oob_file.seek(page * self.spare_size)
            self.dataram = bytearray(self.nand_file.read(self.page_size))
            self.spareram = bytearray(self.oob_file.read(self.spare_size))
            if len(self.dataram) != self.page_size or len(self.spareram) != self.spare_size:
                raise EOFError(f"truncated NAND/OOB at physical page 0x{page:X}")

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
            return struct.unpack_from("<I", self.dataram, offset-0x400)[0]
        elif size == 4 and offset >= 0x10020 and offset < 0x100A0:
            return struct.unpack_from("<I", self.spareram, offset-0x10020)[0]
        elif size == 2 and offset >= 0x10020 and offset < 0x100A0:
            return struct.unpack_from("<H", self.spareram, offset-0x10020)[0]
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
                    self.override_page[(self.physical_block(), x)] = b"\xFF" * self.page_size
                    self.override_spare[(self.physical_block(), x)] = b"\xFF" * self.spare_size
                self.int = 0xFFFF
            elif value == 0x80:
                # Program page
                key = self.page_key()
                page_in_block = key[1]
                print("=> Program page 0x{:X}:0x{:X}".format(self.start_addr_1, page_in_block))
                self.override_page[key] = bytes(self.dataram)
                self.override_spare[key] = bytes(self.spareram)
                self.int = 0xFFFF
            else:
                print("UNKNOWN CMD REG value=0x{:X}".format(value))
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

    if mu is None:
        return
    for name, reg in regs:
        print(">>> {} : 0x{:08X}".format(name, mu.reg_read(reg)))


def post_print(uc, address, size, user_data):
    data = mu.mem_read(0x61a46e48, 0x2000)
    data = data.split(b"\x00", 1)[0]
    print("!! PRINT !! {}".format(data.decode("ascii", errors="replace").rstrip()))


def map_onenand(uc, device, fast=False):
    if not fast:
        uc.mmio_map(0x30000000, 0x20000,
                    lambda uc, offset, size, data: device.read_reg(offset, size), None,
                    lambda uc, offset, size, value, data: device.write_reg(offset, size, value), None)
        return

    # RAM transfers run directly in Unicorn; only device registers need hooks.
    uc.mem_map(0x30000000, 0x20000)

    def reg_read(uc, access, address, size, value, data):
        value = device.read_reg(address - 0x30000000, size)
        uc.mem_write(address, value.to_bytes(size, "little"))

    def reg_write(uc, access, address, size, value, data):
        if address == 0x3001E440 and value == 0x80:
            device.dataram = bytearray(uc.mem_read(0x30000400, device.page_size))
            device.spareram = bytearray(uc.mem_read(0x30010020, device.spare_size))
        device.write_reg(address - 0x30000000, size, value)
        if address == 0x3001E440 and value in (0, 3):
            uc.mem_write(0x30000400, bytes(device.dataram))
            uc.mem_write(0x30010020, bytes(device.spareram))

    uc.hook_add(UC_HOOK_MEM_READ, reg_read, begin=0x3001E000, end=0x3001FFFF)
    uc.hook_add(UC_HOOK_MEM_WRITE, reg_write, begin=0x3001E000, end=0x3001FFFF)


def nonnegative(value):
    number = int(value, 0)
    if number < 0:
        raise argparse.ArgumentTypeError("must be nonnegative")
    return number


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="Reconstruct a Fujitsu FSR STL partition")
    parser.add_argument("partition", type=lambda value: int(value, 16), help="hexadecimal STL partition ID")
    parser.add_argument("output", type=Path)
    parser.add_argument("--nand", type=Path, default=Path("onenand.bin"))
    parser.add_argument("--oob", type=Path, default=Path("onenand.oob"))
    parser.add_argument("--profile", choices=("auto", *PROFILES), default="auto",
                        help="auto detects 512 MiB or 2 GiB layouts by input size")
    parser.add_argument("--start-sector", type=nonnegative, default=0)
    parser.add_argument("--sectors", type=nonnegative, help="read only this many 512-byte sectors")
    return parser.parse_args(argv)


def extract(args, nand_file, oob_file, profile, geometry, bootloader):
    global mu
    mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    onenand = Onenand(nand_file, oob_file, geometry)
    code = bootloader.read_bytes()
    mu.mem_map(0x60C01000, 0x40000)
    mu.mem_write(0x60C01000, code)
    if profile == "2G":
        # This address belongs to the bundled secondbl's 0x68 device table.
        patch_address = 0x60C33274
        if bytes(mu.mem_read(patch_address, 4)) != struct.pack("<HH", 0, 4096):
            raise ValueError("bundled bootloader device table does not match 2G geometry patch")
        mu.mem_write(patch_address, struct.pack("<HH", 0, 8192))

    mu.mem_map(0xE7A90000, 0x2000)
    mu.reg_write(UC_ARM_REG_SP, 0xE7A91FFC)
    mu.mem_map(0x61100000, 0x950000)  # BSS
    mu.mem_map(0x70000000, 0x100000)
    info_ptr, buf_ptr = 0x700F0000, 0x70000000
    map_onenand(mu, onenand, fast=profile == "2G")
    mu.hook_add(UC_HOOK_CODE, post_print, begin=0x60C2FBEC, end=0x60C2FBEC)

    mu.emu_start(0x60C09294, 0x60C09330)  # FSR_STL_Init
    ret = mu.reg_read(UC_ARM_REG_R0)
    if ret:
        raise RuntimeError(f"FSR_STL_Init: 0x{ret:08X}")
    mu.reg_write(UC_ARM_REG_R0, 0)
    mu.reg_write(UC_ARM_REG_R1, args.partition)
    mu.reg_write(UC_ARM_REG_R2, info_ptr)
    mu.reg_write(UC_ARM_REG_R3, 0)
    mu.emu_start(0x60C094DC, 0x60C09910)  # FSR_STL_Open
    ret = mu.reg_read(UC_ARM_REG_R0)
    if ret:
        raise RuntimeError(f"FSR_STL_Open: 0x{ret:08X}")
    total = struct.unpack("<4I", mu.mem_read(info_ptr, 16))[2]
    end = total if args.sectors is None else args.start_sector + args.sectors
    if not args.start_sector <= end <= total:
        raise ValueError(f"requested sector range exceeds partition size ({total} sectors)")
    print(f"partition 0x{args.partition:X}: {total} sectors ({total * 512} bytes)")

    # The 2G layout must not batch across a NAND page: larger requests produced bad data.
    batch = 8 if profile == "2G" else 1
    sector = args.start_sector
    with args.output.open("wb") as outf:
        while sector < end:
            count = min(batch - sector % batch, end - sector)
            mu.reg_write(UC_ARM_REG_SP, 0x700E0000)
            mu.reg_write(UC_ARM_REG_R0, 0)
            mu.reg_write(UC_ARM_REG_R1, args.partition)
            mu.reg_write(UC_ARM_REG_R2, sector)
            mu.reg_write(UC_ARM_REG_R3, count)
            mu.mem_write(0x700E0000, struct.pack("<II", buf_ptr, 0))
            mu.emu_start(0x60C09B48, 0x60C09C84)  # FSR_STL_Read
            ret = mu.reg_read(UC_ARM_REG_R0)
            if ret:
                raise RuntimeError(f"FSR_STL_Read sector {sector}: 0x{ret:08X}; output is partial")
            outf.write(mu.mem_read(buf_ptr, count * 512))
            sector += count
            if sector % 8192 == 0 or sector == end:
                print(f"read {sector - args.start_sector} / {end - args.start_sector} sectors", flush=True)
    print(f"saved {args.output} ({(end - args.start_sector) * 512} bytes)")


def main(argv=None):
    args = parse_args(argv)
    bootloader = Path(__file__).resolve().with_name("secondbl.bin")
    # Reject aliases/hard links as well as literal input paths before truncating output.
    for source in (args.nand, args.oob, bootloader):
        if args.output.resolve() == source.resolve() or (
                args.output.exists() and args.output.samefile(source)):
            raise ValueError("output must not overwrite NAND, OOB or bootloader input")
    with args.nand.open("rb") as nand_file, args.oob.open("rb") as oob_file:
        profile, geometry = select_geometry(
            args.nand.stat().st_size, args.oob.stat().st_size, args.profile)
        print(f"profile={profile}, dies={geometry.dies}, blocks/die={geometry.blocks_per_die}")
        extract(args, nand_file, oob_file, profile, geometry, bootloader)


if __name__ == "__main__":
    try:
        main()
    except unicorn.UcError:
        print_regs()
        raise
    except (OSError, EOFError, ValueError, RuntimeError) as error:
        print(f"error: {error}", file=sys.stderr)
        sys.exit(1)
