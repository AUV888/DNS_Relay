#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "../include/DNS_arguments.h"
#include "../include/DNS_cache.h"
#include "../include/DNS_debug.h"
#include "../include/DNS_server.h"
#include "../include/DNS_struct.h"

volatile sig_atomic_t g_shutdown = 0;

static void sigint_handler(int sig) {
    (void)sig;
    g_shutdown = 1;
    fflush(log_fp);
    cache_destroy(&g_cache);
}

int main(int argc, char* argv[]) {
    long worker_thread_cnt = sysconf(_SC_NPROCESSORS_ONLN);
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
    server_socket_close();
    return 0;
}