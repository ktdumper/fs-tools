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
    for sector in range(len(oob) // 16):
        part = oob[sector * 16 : (sector+1) * 16]
        
        # SSR200 sectors are always two sectors in a row.
        if (flash[sector * 0x200 : sector * 0x200 + 8] == b"SSR200\x00\x00" or 
            flash[(sector-1) * 0x200 : (sector-1) * 0x200 + 8] == b"SSR200\x00\x00"
        ):
            continue

        if part[0] == 0x00:
            continue
            
        if part[1:4] == b"\xFF" * 3:
            continue

        sector_id = struct.unpack_from("<I", part)[0]
        sector_id = sector_id >> 8
        if sector_id in matched:
            print(f"WARN: LSN Duplication (sector number: {hex(sector_id)}, oob offset: {hex(sector * 10)})")
        matched.add(sector_id)
        fat[sector_id * 0x200 : (sector_id+1) * 0x200] = flash[sector * 0x200 : (sector+1) * 0x200]

    with open(sys.argv[3], "wb") as outf:
        outf.write(fat)

if __name__ == "__main__":
    main()