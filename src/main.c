#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "../include/DNS_arguments.h"
#include "../include/DNS_cache.h"
#include "../include/DNS_debug.h"
#include "../include/DNS_server.h"
#include "../include/DNS_struct.h"

/* Shutdown flag.  Written only by the signal handler, polled by the
 * server event loop (and later by every worker thread). */
_Atomic int g_shutdown = 0;

/* Number of worker threads; detected at start-up, before any thread is
 * created.  Used by server_mode_blocking_set(). */
long worker_thread_cnt = 0;

static void sigint_handler(int sig) {
    (void)sig;
    /* Async-signal-safe ONLY: a single lock-free atomic store.
     *
     * The old handler also called fflush(log_fp) and cache_destroy()
     * here.  Neither is async-signal-safe — fflush() takes stdio locks
     * and cache_destroy() takes the cache shard mutexes and calls
     * free() — so a signal arriving at the wrong instruction could
     * deadlock the process or corrupt the heap.  All cleanup now lives
     * on the normal exit path in main(), which runs only after the
     * event loop has observed g_shutdown and returned. */
    atomic_store(&g_shutdown, 1);
}

int main(int argc, char* argv[]) {
    worker_thread_cnt = sysconf(_SC_NPROCESSORS_ONLN);
    printf("This program will run on \033[31m\033[1m%ld\033[0m threads\n\033[0m", worker_thread_cnt);

    parse_arguments(argc, argv);
    printf("Upstream server IPv4: %s\n", dns_server_addr);

    struct sigaction sa;
    sa.sa_handler = sigint_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);

    server_socket_init();
    load_cached_dns_file(g_cache);
    if (blocking_mode) {
        server_mode_blocking_set();
    } else {
        server_mode_non_blocking_set();
    }
    printf("\nexit\n");

    /* Cleanup moved out of the signal handler.  At this point the event
     * loop has returned, so no other code path can be touching the cache
     * or the log file.  Order matters: cache_destroy() and
     * server_socket_close() may still emit debug log records, so the log
     * file must be flushed and closed last. */
    cache_destroy(&g_cache);
    server_socket_close();
    log_close();
    return 0;
}
