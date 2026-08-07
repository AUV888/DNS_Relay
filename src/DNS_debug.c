#include "../include/DNS_debug.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

#include "../include/DNS_arguments.h"
#include "../include/DNS_readlog.h"

FILE* log_fp = NULL;

/* Id of the thread that writes the current record, injected into bits
 * 32..47 of every payload.  Each worker overwrites this with its own
 * 0-based index at start-up; the main thread keeps LOG_THREAD_ID_MAIN.
 * Thread-local by construction: never shared, never locked. */
_Thread_local uint16_t log_thread_id = LOG_THREAD_ID_MAIN;

/* Serializes every writer so that log records can never interleave or
 * tear: one record takes two consecutive fwrite() calls (timestamp +
 * payload), and some debug sequences span several records that must
 * stay contiguous (e.g. CACHE_FIND_SRC + raw domain bytes).
 *
 * Static initializer: the mutex is valid before any thread exists, and
 * it costs nothing when debug_mode == 0 (all writers return early). */
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

void log_lock(void) { pthread_mutex_lock(&log_mutex); }

void log_unlock(void) { pthread_mutex_unlock(&log_mutex); }

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

/* Unlocked core of log_write(): the caller MUST hold log_mutex. */
void log_write_nolock(uint64_t payload) {
    if (debug_mode == 0 || log_fp == NULL)
        return;

    uint64_t ts = (uint64_t)now_us();
    /* The thread id normally arrives embedded in bits 32..47 of the
     * payload (every instrumentation site ORs it in explicitly).  If a
     * site left the field zero — e.g. the three sites in the
     * protocol-only DNS_convert.c, which are off-limits for changes —
     * fill it from this thread's TLS id as a fallback. */
    uint64_t pl = (uint64_t)payload;
    if ((pl & THREAD_MASK) == 0) {
        pl |= THREAD_MASK & ((uint64_t)log_thread_id << 32);
    }

    fwrite(&ts, sizeof(ts), 1, log_fp);
    fwrite(&pl, sizeof(pl), 1, log_fp);
    if (debug_mode == 2) {
        time_t sec = ts / 1000000;
        struct tm* tm_info = localtime(&sec);
        char buf[64];
        strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", tm_info);
        printf("%s.%06llu\t", buf, ts % 1000000);
        log_event_t l = (log_event_t)(payload >> 48);
        read_data(l, log_thread_id);
    }
}

/* Unlocked core of log_write_bytes(): the caller MUST hold log_mutex. */
void log_write_bytes_nolock(const void* data, uint32_t len) {
    if (debug_mode == 0 || len == 0 || data == NULL || log_fp == NULL)
        return;

    fwrite(data, 1, (size_t)len, log_fp);
}

void log_write(uint64_t payload) {
    if (debug_mode == 0)
        return;

    /* The lazy open happens under the mutex, so two workers can never
     * race their way into two FILE* handles on the same file. */
    log_lock();
    if (log_fp == NULL && log_open() != 0) {
        log_unlock();
        return;
    }
    log_write_nolock(payload);
    log_unlock();
}

void log_write_bytes(const void* data, uint32_t len) {
    if (debug_mode == 0 || len == 0 || data == NULL)
        return;

    log_lock();
    if (log_fp == NULL && log_open() != 0) {
        log_unlock();
        return;
    }
    log_write_bytes_nolock(data, len);
    log_unlock();
}
