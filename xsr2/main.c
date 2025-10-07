#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <stdarg.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/stat.h>

int partnum;

typedef uint16_t UINT16;
typedef uint8_t UINT8;
typedef uint32_t UINT32;
typedef uint32_t BOOL32;

void OAM_Debug(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
}

void *OAM_Malloc(size_t sz) {
    void *ptr = malloc(sz);
    memset(ptr, 0, sz);
    return ptr;
}

void OAM_Free(void *ptr) {
    free(ptr);
}

void* OAM_Memset(void *ptr, int ch, size_t sz) {
    return memset(ptr, ch, sz);
}

void* OAM_Memcpy(void *dst, void *src, size_t sz) {
    return memcpy(dst, src, sz);
}

int BML_Init() {
    return 0;
}

int BML_Open() {
    return 0;
}

struct BMLVolSpec {
    UINT16 nPgsPerBlk;
    UINT8 nSctsPerPg;
    UINT8 nLsnPos;
    UINT8 nEccPos;
    UINT8 nReserved8;
    UINT16 nReserved16;
    UINT32 nTrTime;
    UINT32 nTwTime;
    UINT32 nTeTime;
    UINT32 nTfTime;
    UINT32 nNumOfUsBlks;
    BOOL32 bMErasePol;
    UINT32 nEccPol;
    UINT8 aUID[16];
};

int BML_GetVolInfo(int vol, struct BMLVolSpec *spec) {
    spec->nPgsPerBlk = 64;
    spec->nSctsPerPg = 4;
    spec->nLsnPos = 2;
    return 0;
}

struct XSRPartEntry {
    UINT32 nID;
    UINT32 nAttr;
    UINT32 n1stVbn;
    UINT32 nNumOfBlks;
};

void *onenand;
size_t onenand_size;
void *onenand_oob;

struct XSRPartI {
    UINT8 aSig[8];
    UINT32 nVer;
    UINT32 nNumOfPartEntry;
    struct XSRPartEntry stPEntry[31];
};

int BML_LoadPIEntry(int vol, int npart, struct XSRPartEntry *part) {
    uint8_t *end = (uint8_t*)onenand + onenand_size;

    while (1) {
        end -= 512;
        if (memcmp(end, "XSRPARTI", 8) == 0) {
            struct XSRPartI* parts = (void*)end;
            for (int i = 0; i < parts->nNumOfPartEntry; ++i) {
                if (parts->stPEntry[i].nID == npart) {
                    memcpy(part, &parts->stPEntry[i], sizeof(*part));
                    return 0;
                }
            }
        }
    }
}

int OAM_Memcmp(void *a, void *b, size_t sz) {
    return memcmp(a, b, sz);
}

static void hexdump(void *buf, size_t sz) {
    uint8_t *cbuf = buf;
    for (size_t i = 0; i < sz; ++i) {
        if (i % 16 == 0)
            printf("\n");
        printf("%02X ", cbuf[i]);
    }
    printf("\n");
}

int BML_Read(uint32_t nVol, uint32_t nVsn, uint32_t nNumOfScts, void *pMBuf, void *pSBuf, uint32_t nFlag) {
    printf("BML_Read(%d, 0x%x, %d, %p, %p, 0x%08X)\n", nVol, nVsn, nNumOfScts, pMBuf, pSBuf, nFlag);

    if (pMBuf) {
        memcpy(pMBuf, (uint8_t*)onenand + 512 * nVsn, 512 * nNumOfScts);
        // printf("MAIN");
        // hexdump(pMBuf, 512 * nNumOfScts);
    }

    if (pSBuf) {
        memcpy(pSBuf, (uint8_t*)onenand_oob + 16 * nVsn, 16 * nNumOfScts);
        // printf("SPARE");
        // hexdump(pSBuf, 16 * nNumOfScts);
    }
    return 0;
}

int BML_SGLWrite() {
    printf("BML_SGLWrite!!\n");
    return 0;
}

int BML_Write() {
    printf("BML_Write!!\n");
    return 0;
}

struct SGLEntry {
    UINT8 * pBuf;
    UINT16 nSectors;
    UINT8 nFlag;
};

struct SGL {
    UINT8 nElements;
    struct SGLEntry stSGLEntry[9];
};

int BML_SGLRead(UINT32  nVol,  UINT32 nVsn,   UINT32 nNumOfScts, struct SGL   *pstSGL, UINT8 *pSBuf,  UINT32 nFlag) {
    printf("BML_SGLRead(%d, 0x%x, %d, %p, %p, %d)\n", nVol, nVsn, nNumOfScts, pstSGL, pSBuf, nFlag);
    if (nNumOfScts != 1 || pstSGL->nElements != 1 || pstSGL->stSGLEntry[0].nSectors != 1 || pSBuf) {
        printf("BML_SGLRead unsupported args\n");
        abort();
    }

    memcpy(pstSGL->stSGLEntry[0].pBuf, (uint8_t*)onenand + 512 * nVsn, 512);

    return 0;
}

#define STUB(x) void x() {puts(#x);abort();}

STUB(BML_CopyBack);
STUB(BML_Copy);
STUB(BML_MEraseBlk);
STUB(BML_EraseBlk);
STUB(OAM_ResetTimer);
STUB(OAM_GetTime);
STUB(BML_GetDevInfo);
STUB(BML_Close);
STUB(BML_FlushOp);

STUB(down);
STUB(up);
STUB(printk);
int xsr_mutex;
STUB(xsr_get_part_spec);
STUB(xsr_get_stl_info);
STUB(__copy_from_user);
STUB(__memzero);
STUB(__put_user_4);
STUB(__get_user_4);
STUB(__copy_to_user);
STUB(del_gendisk);
STUB(put_disk);
STUB(kfree);
STUB(blk_cleanup_queue);
STUB(__kmalloc);
STUB(kmem_cache_alloc);
STUB(blk_init_queue);
STUB(alloc_disk);
STUB(add_disk);
STUB(malloc_sizes);
STUB(blk_rq_map_sg);
STUB(end_request);
STUB(elv_next_request);
STUB(xsr_unregister_stl_ioctl);
STUB(sec_stl_delete);
STUB(unregister_blkdev);
STUB(xsr_register_stl_ioctl);
STUB(register_blkdev);
STUB(xsr_update_vol_spec);

int STL_Init();
int STL_Open();
int STL_Read();

uint8_t buf[4096];

struct STLInfo {
    uint32_t nTotalLogScts;
    uint32_t nLogSctsPerUnit;
    uint32_t nSamBufFactor;
    uint32_t bASyncMode;
};

struct STLInfo info;

void *mmap_file(const char *filename, int is_data) {
    int fd = open(filename, O_RDONLY);
    void *ret;
    struct stat sb;
    fstat(fd, &sb);
    ret = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    // printf("fd: %d mmap: %x\n", fd, onenand);
    if (is_data)
        onenand_size = sb.st_size;

    if (onenand == MAP_FAILED) {
        perror("mmap");
        abort();
    }

    return ret;
}

int main(int argc, char *argv[]) {
    if (argc != 5) {
        printf("Usage: convert_xsr onenand-bin onenand-oob part-idx output-bin\n");
        return -1;
    }

    onenand = mmap_file(argv[1], 1);
    onenand_oob = mmap_file(argv[2], 0);

    partnum = strtoul(argv[3], NULL, 16);

    printf("Started!\n");

    STL_Init();

    int ret;
    ret = STL_Open(0, partnum, &info);
    printf("STL_Open: %d\n", ret);

    FILE *outf = fopen(argv[4], "wb");

    for (int i = 0; ; ++i) {
        memset(buf, 0xFF, sizeof(buf));
        ret = STL_Read(0, partnum, i, 1, buf);
        if (ret == 0x80020000)
            break;
        fwrite(buf, 512, 1, outf);
    }
    fclose(outf);

    printf("\n\ndone!\n");

    // hexdump(buf, sizeof(buf));

    return 0;
}
