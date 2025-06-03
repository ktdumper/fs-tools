import sys


def main():
    with open(sys.argv[1], "rb") as inf:
        data = bytearray(inf.read())
    BPB_BytsPerSec = int.from_bytes(data[11:13], byteorder="little")
    BPB_RsvdSecCnt = int.from_bytes(data[14:16], byteorder="little")
    BPB_NumFATs = data[16]
    BPB_FATSz16 = int.from_bytes(data[22:24], byteorder="little")
    print(f"BPB_BytsPerSec: {BPB_BytsPerSec}")
    print(f"BPB_RsvdSecCnt: {BPB_RsvdSecCnt}")
    print(f"BPB_NumFATs: {BPB_NumFATs}")
    print(f"BPB_FATSz16: {BPB_FATSz16}")

    cur = BPB_RsvdSecCnt
    for fatidx in range(BPB_NumFATs):
        start = cur
        end = cur + BPB_FATSz16

        bad_fat = data[start * BPB_BytsPerSec:end * BPB_BytsPerSec]
        out_fat = b""
        for x in range(len(bad_fat) // 512):
            entry = x*512
            out_fat += bad_fat[entry+16:entry+512]
        out_fat += b"\x00" * (len(bad_fat) - len(out_fat))

        data[start * BPB_BytsPerSec:end * BPB_BytsPerSec] = out_fat

        cur = end

    with open(sys.argv[2], "wb") as outf:
        outf.write(data)


if __name__ == "__main__":
    main()
