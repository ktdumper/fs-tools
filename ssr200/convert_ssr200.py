import sys
import struct

def main(nand_path, oob_path, out_dir):
    with open(nand_path, "rb") as inf:
        flash = inf.read()
    with open(oob_path, "rb") as inf:
        oob = inf.read()

    assert len(flash) % 512 == 0
    assert len(oob) % 16 == 0
    assert (len(oob) // 16) * 512 == len(flash)

    matched = set()

    fat = bytearray(0x200 * 0x10000)
    for block in range(len(oob) // 16):
        part = oob[block*16:(block+1)*16]

        if part[0] == 0x00:
            #assert part[0:4] == b"\x00\x00\x00\x00"
            continue

        if part[0:8] == b"\xFF" * 8:
            continue

        if part[0:4] == part[4:8]:
            #assert part[0] in [0xFE, 0xFC, 0xF8]
            pass

        if part[0:4] == part[4:8]:
            sector = struct.unpack_from("<I", part)[0]
            sector = sector >> 8
            #assert sector not in matched
            matched.add(sector)
            fat[0x200*sector:0x200*(sector+1)] = flash[0x200*block:0x200*(block+1)]

    with open(out_dir, "wb") as outf:
        outf.write(fat)


if __name__ == "__main__":
    nand_path = sys.argv[1]
    oob_path = sys.argv[2]
    out_dir = sys.argv[3]
    main(nand_path, oob_path, out_dir)
