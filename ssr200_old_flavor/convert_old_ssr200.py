import sys
import struct


def main():
    with open(sys.argv[1], "rb") as inf:
        flash = inf.read()
    with open(sys.argv[2], "rb") as inf:
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

        if part[0x0C:0x10] != b"\xFF"*4:
            sector = struct.unpack_from("<I", part)[0]
            sector = sector >> 8
            assert sector not in matched
            if sector in matched: print(f"WARN: (sector number: {hex(sector)}, oob offset: {hex(block)})")
            matched.add(sector)
            fat[0x200*sector:0x200*(sector+1)] = flash[0x200*block:0x200*(block+1)]

    with open(sys.argv[3], "wb") as outf:
        outf.write(fat)

if __name__ == "__main__":
    main()
