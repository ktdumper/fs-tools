#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <inttypes.h>
#include <sys/mman.h>
#include <unistd.h>
#include <pthread.h>

void printk(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
}

void *__memzero(void *dst, size_t sz) {
    return memset(dst, 0, sz);
}

void *__kmalloc(size_t sz, int flags) {
    return malloc(sz);
}

void init_waitqueue_head() {}
void cond_resched() { sleep(1); }

#define STUB(x) void x() {puts(#x);abort();}

STUB(Hcm_led_blink);
STUB(__up_wakeup);
STUB(__down_failed);
STUB(__copy_to_user);
STUB(kmem_cache_alloc);
STUB(__copy_from_user);
STUB(kfree);
STUB(malloc_sizes);
STUB(__put_user_4);
STUB(put_disk);
STUB(blk_cleanup_queue);
STUB(blk_init_queue);
STUB(alloc_disk);
STUB(add_disk);
STUB(sub_preempt_count);
STUB(blk_rq_map_sg);
STUB(del_gendisk);
STUB(elv_next_request);
STUB(add_preempt_count);
STUB(end_that_request_chunk);
STUB(add_disk_randomness);
STUB(elv_dequeue_request);
STUB(end_that_request_last);
STUB(unregister_blkdev);
STUB(preempt_schedule);
STUB(blkdio_unregister);
STUB(register_blkdev);
STUB(blkdio_register);
STUB(Hcm_romdata_read_knl);
STUB(Hcm_romdata_write_knl);
STUB(syserr_TimeStamp);
STUB(do_gettimeofday);
STUB(udelay);
STUB(__ioremap);
STUB(vfree);
STUB(vmalloc);

uint8_t info[4096];

static void hexdump(void *buf, size_t sz) {
    uint8_t *cbuf = buf;
    for (size_t i = 0; i < sz; ++i) {
        if (i % 16 == 0)
            printf("\n");
        printf("%02X ", cbuf[i]);
    }
    printf("\n");
}

uint8_t buf[512];

int main() {
    setbuf(stdout, NULL);

    int ret;
    printf("Low-level fsr dumper\n");


    ret = FSR_STL_Init();
    printf("FSR_STL_Init: 0x%x\n", ret);

    ret = FSR_STL_Open(0, 0x15, &info, 0);
    printf("FSR_STL_Open: 0x%x\n", ret);

    FILE *outf = fopen("output.bin", "wb");

    for (int i = 0; ; i++) {
        memset(buf, 0xAA, sizeof(buf));
        ret = FSR_STL_Read(0, 0x15, i, 1, buf, 0);
        printf("FSR_STL_Read(%d): 0x%x\n", i, ret);

        if (ret != 0) break;

        fwrite(buf, sizeof(buf), 1, outf);
    }

    fclose(outf);

    return 0;
}
