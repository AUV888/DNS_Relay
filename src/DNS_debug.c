#include "../include/DNS_debug.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

#include "../include/DNS_arguments.h"

FILE* log_fp = NULL;

static inline uint64_t now_us(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000ULL + (uint64_t)tv.tv_usec;
}

int log_open(void) {
    if (log_fp != NULL)
        return 0;
    if (log_file[0] == '\0')
        return -1;

    log_fp = fopen(log_file, "ab");
    if (!log_fp) {
        fprintf(stderr,
                "log_open: failed to open '%s' "
                "(make sure the parent directory exists)\n",
                log_file);
        return -1;
    }
    setvbuf(log_fp, NULL, _IOFBF, 64 * 1024);
    return 0;
}

void log_close(void) {
    if (log_fp) {
        fflush(log_fp);
        fclose(log_fp);
        log_fp = NULL;
    }
}

void log_write(uint64_t payload) {
    if (debug_mode == 0)
        return;

    if (log_fp == NULL) {
        if (log_open() != 0)
            return;
    }

    uint64_t ts = (uint64_t)now_us();
    uint64_t pl = (uint64_t)payload;

    fwrite(&ts, sizeof(ts), 1, log_fp);
    fwrite(&pl, sizeof(payload), 1, log_fp);
}

void log_write_bytes(const void* data, uint32_t len) {
    if (debug_mode == 0 || len == 0 || data == NULL)
        return;

    if (log_fp == NULL) {
        if (log_open() != 0)
            return;
    }

    fwrite(data, 1, (size_t)len, log_fp);
}