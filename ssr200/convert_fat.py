import sys
import struct
import argparse
 
def remove_checksum(fat: bytes) -> bytes:
    """Remove the 0x10 header every 0x200 bytes within the FAT area."""
    ret = b""

    for off in range(len(fat) // 0x200):
        entry = off * 0x200

        if fat[entry : entry + 4] != b"\xFF\xFF\x01\x00":
            raise ValueError("There is no checksum header")
        
        ret += fat[entry + 0x10 : entry + 0x200]
    
    ret += b"\x00" * (len(fat) - len(ret))
    return ret

def normalize_fat(fat: bytes, dir_first_clusters: list) -> bytearray:
    """
    This FAT alternately stores the new directory table and the old directory table on the clusters.
    This function corrects the cluster chain in the FAT area.
    """
    ret = bytearray(fat)
    ret[0:4] = fat[0:4]

    for i, c in enumerate(dir_first_clusters):
        print(f"[{i} Directory]")
        try:
            cluster_chain = get_cluster_chain(fat, c)
        except ValueError as e:
            print("Skip due to invalid cluster chain:", e)
            continue

        # Remove the odd numbers and add a EOF.
        filtered = cluster_chain[0:-1:2] + cluster_chain[-1:]

        print(f"Original Chain: {cluster_chain}")
        print(f"Changed Chain: {filtered}")
        
        for c in cluster_chain[:-1]:
            ret[c*2 : c*2 + 2] = b"\x00\x00"

        for i, c in enumerate(filtered):
            if (i+1) <= (len(filtered) - 1):
                ret[c*2 : c*2 + 2] = filtered[i+1].to_bytes(2, "little")

    assert len(ret) == len(fat)
    return ret

def remove_duplicate_entries(root_dir: bytes) -> bytes:
    """
    As there is no cluster chain in the root directory table, This function delete the entry itself.
    """
    ret = b""
    entry_names = []
    for off in range(0, len(root_dir), 0x20):
        entry_data = root_dir[off : off + 0x20]
        name = entry_data[0 : 0xB]

        if all(n == 0 for n in name):
            continue

        if name in entry_names:
            continue

        ret += entry_data
        entry_names.append(name)

    ret += b"\x00" * (len(root_dir) - len(ret))
    return ret


def remove_invalid_field(image: bytes, fat: bytes, dir_first_clusters: list, bpb: dict, root_dir_start: int, root_dir_end: int) -> bytearray:
    """Overwrite DIR_NTRes, DIR_CrtTimeTenth, and DIR_CrtTime of all entries to 00."""
    ret = bytearray(image)


    def overwrite_field(entry: bytes) -> bytearray:
        if len(entry) != 0x20:
            raise ValueError("The entry size is not 0x20.")
        
        _entry = bytearray(entry)
        
        if entry[0xB] == 0x0F:
            return _entry
        
        _entry[0xC : 0x16] = b"\x00" * 0xA

        return _entry

    for off in range(root_dir_start, root_dir_end, 0x20):
        ret[off + 0 : off + 0x20] = overwrite_field(ret[off + 0 : off + 0x20])

    for c1 in dir_first_clusters:
        try:
            cluster_chain = get_cluster_chain(fat, c1)
        except ValueError as e:
            print("Skip due to invalid cluster chain:", e)
            continue

        # Remove the odd numbers
        filtered = cluster_chain[0:-1:2]

        for c2 in filtered:
            cluster_start = cluster_to_offset(bpb, c2) 
            cluster_end = cluster_to_offset(bpb, c2+1)
            for off in range(cluster_start, cluster_end, 0x20):
                ret[off + 0 : off + 0x20] = overwrite_field(ret[off + 0 : off + 0x20])
    return ret

def is_dir_entry(entry: bytes) -> bool:
    if len(entry) != 0x20:
        raise ValueError("The entry size is not 0x20.")

    name0 = entry[0]
    attr  = entry[0xB]

    # 2E: "."
    if name0 in [0x00, 0xE5, 0x2E]:
        return False

    # LFN
    if attr == 0x0F:
        return False

    if not (attr & 0x10):
        return False

    first_cluster = int.from_bytes(entry[26:28], "little")
    if first_cluster < 2:
        return False

    return True

def collect_dir_first_clusters(image: bytes, root_dir: bytes, fat: bytes, bpb: dict) -> list:
    dir_first_clusters = []

    count = 0
    def collect(dir_data: bytes):
        nonlocal count
        for off in range(0, len(dir_data), 0x20):
            entry = dir_data[off : off + 0x20]
            if is_dir_entry(entry):
                cluster = int.from_bytes(entry[0x1A : 0x1C], "little")
                if cluster in dir_first_clusters:
                    continue
                dir_first_clusters.append(cluster)
                print(f"{count}: {entry[0x0 : 0xB].decode('cp932', errors='ignore')}")
                count += 1

                next_dir_data = b""
                try:
                    cluster_chain = get_cluster_chain(fat, cluster)
                except ValueError as e:
                    print("Skip due to invalid cluster chain:", e)
                    continue
                for c in cluster_chain[:-1:2]:
                    start = cluster_to_offset(bpb, c)
                    end = cluster_to_offset(bpb, c+1)
                    next_dir_data += image[start : end]
                collect(next_dir_data)

    collect(root_dir)

    return dir_first_clusters

def get_cluster_chain(fat: bytes, first_cluster: int) -> list:
    entry_chain = []
    cur_entry = first_cluster
    while True:
        if cur_entry == 0:
            raise ValueError("The cluster chain contains a zero.")
        
        if cur_entry < 0xFFF8 and cur_entry*2 + 2 > len(fat):
            raise ValueError("Cluster chain outside the FAT range.")

        entry_chain.append(cur_entry)
        if cur_entry >= 0xFFF8:
            break

        cur_entry = int.from_bytes(fat[cur_entry*2 : cur_entry*2 + 2], "little")

    return entry_chain

def cluster_to_offset(bpb: dict, cluster: int) -> int:
    bytes_per_sec = bpb["BPB_BytsPerSec"]
    sec_per_clus = bpb["BPB_SecPerClus"]

    # root directory sectors (FAT12/16)
    root_dir_sectors = (bpb["BPB_RootEntCnt"] * 32 + (bytes_per_sec - 1)) // bytes_per_sec

    # data start sector
    data_start_sector = (
        bpb["BPB_RsvdSecCnt"]
        + bpb["BPB_NumFATs"] * bpb["BPB_FATSz16"]
        + root_dir_sectors
    )

    # convert cluster number to offset
    data_area_offset = data_start_sector * bytes_per_sec
    bytes_per_cluster = bytes_per_sec * sec_per_clus

    return data_area_offset + (cluster - 2) * bytes_per_cluster

def parse_fat16_bpb(boot_sector: bytes) -> dict:
    if len(boot_sector) != 0x200:
        raise ValueError("Boot sector must be exactly 512 (0x200) bytes.")

    if boot_sector[0x1FE:0x200] != b"\x55\xAA":
        raise ValueError("The boot signature is different.")

    BS_jmpBoot     = boot_sector[0:3]
    BS_OEMName     = boot_sector[3:11].decode('ascii', errors='replace').rstrip()
    BPB_BytsPerSec = struct.unpack_from("<H", boot_sector, 11)[0]
    BPB_SecPerClus = struct.unpack_from("<B", boot_sector, 13)[0]
    BPB_RsvdSecCnt = struct.unpack_from("<H", boot_sector, 14)[0]
    BPB_NumFATs    = struct.unpack_from("<B", boot_sector, 16)[0]
    BPB_RootEntCnt = struct.unpack_from("<H", boot_sector, 17)[0]
    BPB_TotSec16   = struct.unpack_from("<H", boot_sector, 19)[0]
    BPB_Media      = struct.unpack_from("<B", boot_sector, 21)[0]
    BPB_FATSz16    = struct.unpack_from("<H", boot_sector, 22)[0]
    BPB_SecPerTrk  = struct.unpack_from("<H", boot_sector, 24)[0]
    BPB_NumHeads   = struct.unpack_from("<H", boot_sector, 26)[0]
    BPB_HiddSec    = struct.unpack_from("<I", boot_sector, 28)[0]
    BPB_TotSec32   = struct.unpack_from("<I", boot_sector, 32)[0]
    BS_DrvNum      = struct.unpack_from("<B", boot_sector, 36)[0]
    BS_Reserved1   = struct.unpack_from("<B", boot_sector, 37)[0]
    BS_BootSig     = struct.unpack_from("<B", boot_sector, 38)[0]
    BS_VolID       = struct.unpack_from("<I", boot_sector, 39)[0]
    BS_VolLab      = boot_sector[43:54].decode("ascii", errors="replace").rstrip()
    BS_FilSysType  = boot_sector[54:62].decode("ascii", errors="replace").rstrip()

    if BS_VolLab != "NECVOL":
        raise ValueError("It's not 'NECVOL' FAT.")

    return {
        "BS_jmpBoot": BS_jmpBoot,
        "BS_OEMName": BS_OEMName,
        "BPB_BytsPerSec": BPB_BytsPerSec,
        "BPB_SecPerClus": BPB_SecPerClus,
        "BPB_RsvdSecCnt": BPB_RsvdSecCnt,
        "BPB_NumFATs": BPB_NumFATs,
        "BPB_RootEntCnt": BPB_RootEntCnt,
        "BPB_TotSec16": BPB_TotSec16,
        "BPB_Media": BPB_Media,
        "BPB_FATSz16": BPB_FATSz16,
        "BPB_SecPerTrk": BPB_SecPerTrk,
        "BPB_NumHeads": BPB_NumHeads,
        "BPB_HiddSec": BPB_HiddSec,
        "BPB_TotSec32": BPB_TotSec32,
        "BS_DrvNum": BS_DrvNum,
        "BS_Reserved1": BS_Reserved1,
        "BS_BootSig": BS_BootSig,
        "BS_VolID": BS_VolID,
        "BS_VolLab": BS_VolLab,
        "BS_FilSysType": BS_FilSysType,
    }

def get_fat_offsets(bpb: dict) -> list:
    cur = bpb["BPB_RsvdSecCnt"]
    fat_offsets = []
    for fatidx in range(bpb["BPB_NumFATs"]):
        start = cur * bpb["BPB_BytsPerSec"]
        end = (cur + bpb["BPB_FATSz16"]) * bpb["BPB_BytsPerSec"]
        fat_offsets.append([start, end])
        cur += bpb["BPB_FATSz16"]
    return fat_offsets

def main():
    parser = argparse.ArgumentParser(description="Carve apps for F504iS")
    parser.add_argument("input")
    parser.add_argument("output")
    parser.add_argument(
        "-dn", "--disable-normalize", action="store_true",
        help="Do not delete duplicate directory tables. (For P2102V)"
    )
    args = parser.parse_args()
    enable_normalize = not args.disable_normalize

    with open(args.input, "rb") as inf:
        image = bytearray(inf.read())

    bpb = parse_fat16_bpb(image[0 : 0x200])
    print("BPB Infomation:", bpb)

    # Overwrite BS_jmpBoot
    image[0 : 2] = b"\xEB\x3C"

    # Overwrite BS_VolLab
    image[0x2B : 0x36] = b"NO NAME    "

    root_dir_start = (bpb["BPB_RsvdSecCnt"] + bpb["BPB_NumFATs"] * bpb["BPB_FATSz16"]) * bpb["BPB_BytsPerSec"]
    root_dir_end = root_dir_start + (bpb["BPB_RootEntCnt"] * 32)
    print(f"Root Directory Offset: {hex(root_dir_start)} - {hex(root_dir_end)}")
    print(f"Cluster Offset Calculation Formula: {cluster_to_offset(bpb, 2)} + (c - 2) * {bpb['BPB_BytsPerSec'] * bpb['BPB_SecPerClus']}")
    
    if enable_normalize:
        image[root_dir_start : root_dir_end] = remove_duplicate_entries(image[root_dir_start : root_dir_end])

    fat_offsets = get_fat_offsets(bpb)

    for i, (start, end) in enumerate(fat_offsets):
        print(f"\n===== FAT {i} (offset: {hex(start)}) =====")

        try:
            image[start : end] = remove_checksum(image[start : end])
        except ValueError:
            print(f"There is no checksum header at {hex(start)}, skipping.")

        dir_first_clusters = collect_dir_first_clusters(image, image[root_dir_start : root_dir_end], image[start : end], bpb)

        if enable_normalize:
            image[start : end] = normalize_fat(image[start : end], dir_first_clusters)

        if i == 0:
            image = remove_invalid_field(image, image[start : end], dir_first_clusters, bpb, root_dir_start, root_dir_end)

    with open(args.output, "wb") as outf:
        outf.write(image)

if __name__ == "__main__":
    main()
