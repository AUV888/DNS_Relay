#include "../include/DNS_server.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

/* Helper: set a file descriptor to non-blocking mode. */
static int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0)
        return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

#include "../include/DNS_arguments.h"
#include "../include/DNS_cache.h"
#include "../include/DNS_convert.h"
#include "../include/DNS_debug.h"
#include "../include/DNS_id.h"
#include "../include/DNS_struct.h"

int local_socket_fd = -1;
int remote_socket_fd = -1;
int sock_addr_len;

struct sockaddr_in local_addr;
struct sockaddr_in remote_addr;

cache_set* g_cache;

void server_socket_init() {
    log_event_t l;
    sock_addr_len = sizeof(local_addr);

    memset(&local_addr, 0, sizeof(local_addr));
    memset(&remote_addr, 0, sizeof(remote_addr));

    local_addr.sin_family = AF_INET;
    local_addr.sin_addr.s_addr = INADDR_ANY;
    local_addr.sin_port = htons(dns_listen_port);

    remote_addr.sin_family = AF_INET;
    remote_addr.sin_addr.s_addr = inet_addr(dns_server_addr);
    remote_addr.sin_port = htons(dns_upstream_port);

    g_cache = create_hset();
    cache_init(g_cache);
    /* Initialize the sharded ID map (per-shard mutexes + cursors).  The
     * old table relied on static zero-initialization; the sharded one
     * needs explicit pthread_mutex_init before first use. */
    id_map_init();

    if (blocking_mode) {
        /* Multi-threaded path: every worker creates its own socket pair in
         * worker_main(), with SO_REUSEPORT on the listening socket so the
         * kernel spreads clients across workers by 4-tuple hash.
         *
         * Deliberately NOT creating a shared listening socket here: it
         * would join the SO_REUSEPORT group and silently swallow its share
         * of incoming queries, because nobody would ever read from it. */
        if (debug_mode) {
            l = SOCKET_INIT_SUCCESS;
            uint64_t pl = (EVENT_MASK & ((uint64_t)l << 48)) |
                (THREAD_MASK & ((uint64_t)log_thread_id << 32));
            log_write(pl);
        }
        return;
    }

    /* Legacy single-threaded (non-blocking) path: shared global sockets. */
    local_socket_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (local_socket_fd < 0) {
        if (debug_mode) {
            l = LOCAL_SOCKET_FAILED;
            uint64_t pl = (EVENT_MASK & ((uint64_t)l << 48)) |
                (THREAD_MASK & ((uint64_t)log_thread_id << 32));
            log_write(pl);
        }
        exit(EXIT_FAILURE);
    }
    remote_socket_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (remote_socket_fd < 0) {
        if (debug_mode) {
            l = REMOTE_SOCKET_FAILED;
            uint64_t pl = (EVENT_MASK & ((uint64_t)l << 48)) |
                (THREAD_MASK & ((uint64_t)log_thread_id << 32));
            log_write(pl);
        }
        exit(EXIT_FAILURE);
    }

    int opt = 1;
    if (setsockopt(local_socket_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        if (debug_mode) {
            l = SOCKET_OPT_FAILED;
            uint64_t pl = (EVENT_MASK & ((uint64_t)l << 48)) |
                (THREAD_MASK & ((uint64_t)log_thread_id << 32));
            log_write(pl);
        }
        exit(EXIT_FAILURE);
    }

    if (bind(local_socket_fd, (const struct sockaddr*)&local_addr, sizeof(local_addr)) < 0) {
        if (debug_mode) {
            l = SOCKET_BIND_FAILED;
            uint64_t pl = (EVENT_MASK & ((uint64_t)l << 48)) |
                (THREAD_MASK & ((uint64_t)log_thread_id << 32));
            log_write(pl);
        }
        exit(EXIT_FAILURE);
    }

    /* Legacy path only: make both global sockets non-blocking so
     * recvfrom returns EAGAIN when the kernel buffer is empty.  (The
     * multi-threaded path returned early above and does the same per
     * worker inside worker_main.) */
    if (set_nonblocking(local_socket_fd) < 0 || set_nonblocking(remote_socket_fd) < 0) {
        if (debug_mode) {
            l = NON_BLOCK_MODE_LOCAL_FSETFL_ERR;
            uint64_t pl = (EVENT_MASK & ((uint64_t)l << 48)) |
                (THREAD_MASK & ((uint64_t)log_thread_id << 32));
            log_write(pl);
        }
        exit(EXIT_FAILURE);
    }

    if (debug_mode) {
        l = SOCKET_INIT_SUCCESS;
        uint64_t pl = (EVENT_MASK & ((uint64_t)l << 48)) |
            (THREAD_MASK & ((uint64_t)log_thread_id << 32));
        log_write(pl);
    }
}

void server_socket_close() {
    log_event_t l;
    if (local_socket_fd != -1) {
        close(local_socket_fd);
        local_socket_fd = -1;
    }
    if (remote_socket_fd != -1) {
        close(remote_socket_fd);
        remote_socket_fd = -1;
    }
    if (debug_mode) {
        l = SOCKET_CLOSE_SUCCESS;
        uint64_t pl = (EVENT_MASK & ((uint64_t)l << 48)) |
            (THREAD_MASK & ((uint64_t)log_thread_id << 32));
        log_write(pl);
    }
}

/* -----------------------------------------------------------------------
 * Multi-threaded blocking mode.
 *
 * server_mode_blocking_set() spawns worker_thread_cnt worker threads and
 * blocks until all of them have exited.  Each worker owns a private
 * socket pair and runs its own copy of the original select() event loop.
 * The only state shared between workers is the sharded cache, the
 * sharded ID map and the debug log — all mutex-protected.
 *
 * SO_REUSEPORT on every worker's listening socket lets them all bind the
 * same port; the kernel then hashes each incoming packet's 4-tuple to
 * exactly one socket, so there is no thundering herd and no shared fd.
 * ----------------------------------------------------------------------- */
static void* worker_main(void* arg) {
    worker_ctx_t* ctx = (worker_ctx_t*)arg;

    /* Tag every log record this worker writes with its 0-based index.
     * Must happen before the first log_write() of this thread; the main
     * thread keeps LOG_THREAD_ID_MAIN. */
    log_thread_id = (uint16_t)ctx->tid;

    ctx->local_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (ctx->local_fd < 0) {
        if (debug_mode) {
            log_event_t l = LOCAL_SOCKET_FAILED;
            uint64_t pl = (EVENT_MASK & ((uint64_t)l << 48)) |
                (THREAD_MASK & ((uint64_t)log_thread_id << 32));
            log_write(pl);
        }
        return NULL;
    }

    int opt = 1;
    if (setsockopt(ctx->local_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0 ||
        setsockopt(ctx->local_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) < 0) {
        if (debug_mode) {
            log_event_t l = SOCKET_OPT_FAILED;
            uint64_t pl = (EVENT_MASK & ((uint64_t)l << 48)) |
                (THREAD_MASK & ((uint64_t)log_thread_id << 32));
            log_write(pl);
        }
        close(ctx->local_fd);
        return NULL;
    }

    /* local_addr is read-only from this point on (filled once by
     * server_socket_init before any worker was created). */
    if (bind(ctx->local_fd, (const struct sockaddr*)&local_addr, sizeof(local_addr)) < 0) {
        if (debug_mode) {
            log_event_t l = SOCKET_BIND_FAILED;
            uint64_t pl = (EVENT_MASK & ((uint64_t)l << 48)) |
                (THREAD_MASK & ((uint64_t)log_thread_id << 32));
            log_write(pl);
        }
        close(ctx->local_fd);
        return NULL;
    }

    /* Each worker also owns its upstream socket: replies from the
     * upstream server match this socket's 4-tuple, so they always come
     * back to the very worker that forwarded the query. */
    ctx->remote_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (ctx->remote_fd < 0) {
        if (debug_mode) {
            log_event_t l = REMOTE_SOCKET_FAILED;
            uint64_t pl = (EVENT_MASK & ((uint64_t)l << 48)) |
                (THREAD_MASK & ((uint64_t)log_thread_id << 32));
            log_write(pl);
        }
        close(ctx->local_fd);
        return NULL;
    }

    /* Non-blocking fds let the loop drain every pending datagram in one
     * select() wake-up instead of returning to select after each one. */
    if (set_nonblocking(ctx->local_fd) < 0 || set_nonblocking(ctx->remote_fd) < 0) {
        if (debug_mode) {
            log_event_t l = NON_BLOCK_MODE_LOCAL_FSETFL_ERR;
            uint64_t pl = (EVENT_MASK & ((uint64_t)l << 48)) |
                (THREAD_MASK & ((uint64_t)log_thread_id << 32));
            log_write(pl);
        }
        close(ctx->local_fd);
        close(ctx->remote_fd);
        return NULL;
    }

    int maxfd = (ctx->local_fd > ctx->remote_fd ? ctx->local_fd : ctx->remote_fd) + 1;

    /* Per-worker throttle counter for the timeout heartbeat log. */
    int timeout_cnt = 0;

    while (!atomic_load(&g_shutdown)) {
        fd_set rset;
        FD_ZERO(&rset);
        FD_SET(ctx->local_fd, &rset);
        FD_SET(ctx->remote_fd, &rset);

        /* Wake up at least once per second so we can run housekeeping. */
        struct timeval tv = {1, 0};
        int n = select(maxfd, &rset, NULL, NULL, &tv);

        if (n < 0) {
            if (errno == EINTR) {
                if (debug_mode) {
                    log_event_t l = BLOCK_MODE_ERRNO_EINTR;
                    uint64_t pl = (EVENT_MASK & ((uint64_t)l << 48)) |
                        (THREAD_MASK & ((uint64_t)log_thread_id << 32));
                    log_write(pl);
                }
                continue;  // interrupted by signal, retry
            }
            if (debug_mode) {
                log_event_t l = BLOCK_MODE_ERRNO_SELECT;
                uint64_t pl = (EVENT_MASK & ((uint64_t)l << 48)) |
                    (THREAD_MASK & ((uint64_t)log_thread_id << 32));
                log_write(pl);
            }
            break;
        }

        if (n == 0) {
            // Timeout: run periodic housekeeping, then go back to sleep.
            // Log throttle: only write a BLOCK_MODE_TIMEOUT record every
            // 30 timeouts (30s) to avoid flooding the log.
            timeout_cnt++;
            if (debug_mode) {
                if (timeout_cnt >= 30) {
                    log_event_t l = BLOCK_MODE_TIMEOUT;
                    uint64_t pl = (EVENT_MASK & ((uint64_t)l << 48)) |
                        (THREAD_MASK & ((uint64_t)log_thread_id << 32));
                    log_write(pl);
                    timeout_cnt = 0;
                }
            }
            /* Only worker 0 sweeps the ID map.  Every shard is
             * mutex-protected so the sweep is safe to run, but doing it
             * N times per second would be pure lock contention. */
            if (ctx->tid == 0) {
                id_map_sweep_timeout();
            }
            continue;
        }

        /* Drain all pending packets from each ready socket so that the
         * kernel buffer never builds up across select() calls. */
        if (FD_ISSET(ctx->local_fd, &rset)) {
            while (1) {
                if (debug_mode) {
                    log_event_t l = BLOCK_MODE_LOCAL_RECEIVE;
                    uint64_t pl = (EVENT_MASK & ((uint64_t)l << 48)) |
                        (THREAD_MASK & ((uint64_t)log_thread_id << 32));
                    log_write(pl);
                }
                int local = local_receive(ctx);
                if (debug_mode) {
                    log_event_t l = BLOCK_MODE_LOCAL_RECEIVE_NUM;
                    uint64_t pl =
                        (EVENT_MASK & ((uint64_t)l << 48)) |
                        (THREAD_MASK & ((uint64_t)log_thread_id << 32)) |
                        (INFO_MASK & (uint64_t)local);
                    log_write(pl);
                }
                if (local == 0)
                    break;
            }
        }
        if (FD_ISSET(ctx->remote_fd, &rset)) {
            while (1) {
                if (debug_mode) {
                    log_event_t l = BLOCK_MODE_REMOTE_RECEIVE;
                    uint64_t pl = (EVENT_MASK & ((uint64_t)l << 48)) |
                        (THREAD_MASK & ((uint64_t)log_thread_id << 32));
                    log_write(pl);
                }
                int remote = remote_receive(ctx);
                if (debug_mode) {
                    log_event_t l = BLOCK_MODE_REMOTE_RECEIVE_NUM;
                    uint64_t pl =
                        (EVENT_MASK & ((uint64_t)l << 48)) |
                        (THREAD_MASK & ((uint64_t)log_thread_id << 32)) |
                        (INFO_MASK & (uint64_t)remote);
                    log_write(pl);
                }
                if (remote == 0)
                    break;
            }
        }
    }

    close(ctx->local_fd);
    close(ctx->remote_fd);
    ctx->local_fd = -1;
    ctx->remote_fd = -1;
    return NULL;
}

void server_mode_blocking_set() {
    if (debug_mode) {
        log_event_t l = BLOCK_MODE_START;
        uint64_t pl = (EVENT_MASK & ((uint64_t)l << 48)) |
            (THREAD_MASK & ((uint64_t)log_thread_id << 32));
        log_write(pl);
    }

    long n = worker_thread_cnt > 0 ? worker_thread_cnt : 1;
    pthread_t* tids = (pthread_t*)malloc((size_t)n * sizeof(pthread_t));
    worker_ctx_t* ctxs = (worker_ctx_t*)malloc((size_t)n * sizeof(worker_ctx_t));
    if (!tids || !ctxs) {
        free(tids);
        free(ctxs);
        return;
    }

    long started = 0;
    for (long i = 0; i < n; i++) {
        ctxs[i].tid = (int)i;
        ctxs[i].local_fd = -1;
        ctxs[i].remote_fd = -1;
        ctxs[i].remote_addr = remote_addr; /* read-only snapshot */
        if (pthread_create(&tids[i], NULL, worker_main, &ctxs[i]) != 0) {
            fprintf(stderr, "failed to start worker thread %ld\n", i);
            break;
        }
        started++;
    }

    /* Wait for every worker; each one exits on its own once it observes
     * g_shutdown (at most ~1s, bounded by the select timeout).  After
     * the joins, no thread can touch the shared structures anymore. */
    for (long i = 0; i < started; i++) {
        pthread_join(tids[i], NULL);
    }

    free(tids);
    free(ctxs);
}

void server_mode_non_blocking_set() {
    int flags;

    log_event_t l;
    if (debug_mode) {
        l = NON_BLOCK_MODE_START;
        uint64_t pl = (EVENT_MASK & ((uint64_t)l << 48)) |
            (THREAD_MASK & ((uint64_t)log_thread_id << 32));
        log_write(pl);
    }
    flags = fcntl(local_socket_fd, F_GETFL, 0);  // get file status flags
    if (flags < 0) {
        if (debug_mode) {
            l = NON_BLOCK_MODE_LOCAL_FGETFL_ERR;
            uint64_t pl = (EVENT_MASK & ((uint64_t)l << 48)) |
                (THREAD_MASK & ((uint64_t)log_thread_id << 32));
            log_write(pl);
        }
        return;
    }
    if (fcntl(local_socket_fd, F_SETFL, flags | O_NONBLOCK) < 0) {  // set file status flags
        if (debug_mode) {
            l = NON_BLOCK_MODE_LOCAL_FSETFL_ERR;
            uint64_t pl = (EVENT_MASK & ((uint64_t)l << 48)) |
                (THREAD_MASK & ((uint64_t)log_thread_id << 32));
            log_write(pl);
        }
    }

    flags = fcntl(remote_socket_fd, F_GETFL, 0);
    if (flags < 0) {
        if (debug_mode) {
            l = NON_BLOCK_MODE_REMOTE_FGETFL_ERR;
            uint64_t pl = (EVENT_MASK & ((uint64_t)l << 48)) |
                (THREAD_MASK & ((uint64_t)log_thread_id << 32));
            log_write(pl);
        }
        return;
    }
    if (fcntl(remote_socket_fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        if (debug_mode) {
            l = NON_BLOCK_MODE_REMOTE_FSETFL_ERR;
            uint64_t pl = (EVENT_MASK & ((uint64_t)l << 48)) |
                (THREAD_MASK & ((uint64_t)log_thread_id << 32));
            log_write(pl);
        }
    }

    /* Wrap the two legacy global sockets in a worker context so both
     * modes share exactly the same packet-processing code path. */
    worker_ctx_t ctx;
    ctx.tid = 0;
    ctx.local_fd = local_socket_fd;
    ctx.remote_fd = remote_socket_fd;
    ctx.remote_addr = remote_addr;

    time_t last_sweep = time(NULL);

    while (1) {
        if (atomic_load(&g_shutdown)) {
            return;
        }
        local_receive(&ctx);
        if (debug_mode) {
            l = NON_BLOCK_MODE_LOCAL_RECEIVE;
            uint64_t pl = (EVENT_MASK & ((uint64_t)l << 48)) |
                (THREAD_MASK & ((uint64_t)log_thread_id << 32));
            log_write(pl);
        }
        remote_receive(&ctx);
        if (debug_mode) {
            l = NON_BLOCK_MODE_REMOTE_RECEIVE;
            uint64_t pl = (EVENT_MASK & ((uint64_t)l << 48)) |
                (THREAD_MASK & ((uint64_t)log_thread_id << 32));
            log_write(pl);
        }
        time_t now = time(NULL);
        if (now - last_sweep >= 1) {
            if (debug_mode) {
                l = NON_BLOCK_SWEEP;
                uint64_t pl = (EVENT_MASK & ((uint64_t)l << 48)) |
                    (THREAD_MASK & ((uint64_t)log_thread_id << 32));
                log_write(pl);
            }
            id_map_sweep_timeout();
            last_sweep = now;
        }
    }
}

static inline void cache_answers_from_msg(dns_message_t* msg) {
    if (!g_cache || !msg || !(msg->header))
        return;

    if (DNS_GET_RCODE(msg->header->flags) != DNS_RCODE_OK)
        return;

    dns_resource_record_t* rr = msg->answer;
    while (rr) {
        if (rr->type == DNS_TYPE_A && rr->name != NULL) {
            uint8_t* ipaddr = rr->rd_data.a_record.ip_addr;
            uint32_t ip = ((uint32_t)ipaddr[0] << 24) | ((uint32_t)ipaddr[1] << 16) |
                          ((uint32_t)ipaddr[2] << 8) | (uint32_t)ipaddr[3];
            int ttl = (rr->ttl > 0) ? (int)rr->ttl : 60;
            cache_insert(g_cache, rr->name, ip, ttl);
        }
        rr = rr->next;
    }
    if (debug_mode) {
        log_event_t l = REMOTE_RECEIVE_CACHED_ANSWER_SUCCESS;
        uint64_t pl = (EVENT_MASK & ((uint64_t)l << 48)) |
            (THREAD_MASK & ((uint64_t)log_thread_id << 32));
        log_write(pl);
    }
}

int remote_receive(worker_ctx_t* ctx) {
    uint8_t buf_recv[BUFFER_SIZE];

    log_event_t l;
    struct sockaddr_in upstream_addr;
    socklen_t upstream_len = sizeof(upstream_addr);

    int msg_size = recvfrom(ctx->remote_fd, (void*)buf_recv, sizeof(buf_recv), 0,
                            (struct sockaddr*)&upstream_addr, &upstream_len);
    if (msg_size < 0) {
        /* EAGAIN / EWOULDBLOCK means the buffer is empty — stop draining. */
        return 0;
    }
    if (msg_size < 2) {
        if (debug_mode) {
            l = REMOTE_RECEIVE_MSG_SIZE_ERR;
            uint64_t pl = (EVENT_MASK & ((uint64_t)l << 48)) |
                (THREAD_MASK & ((uint64_t)log_thread_id << 32));
            log_write(pl);
        }
        return 1; /* consumed one (malformed) datagram, keep draining */
    }

    uint16_t new_id_be;
    memcpy(&new_id_be, buf_recv, 2);
    uint16_t new_id = ntohs(new_id_be);

    uint16_t orig_id = 0;
    struct sockaddr_in client_addr;
    if (!id_map_find(new_id, &orig_id, &client_addr)) {  // no original id, drop
        if (debug_mode) {
            l = REMOTE_RECEIVE_NO_ORIG_ID_DROP;
            uint64_t pl = (EVENT_MASK & ((uint64_t)l << 48)) |
                (THREAD_MASK & ((uint64_t)log_thread_id << 32));
            log_write(pl);
        }
        return 1; /* consumed one datagram (dropped), keep draining */
    }

    uint16_t orig_id_be = htons(orig_id);
    memcpy(buf_recv, &orig_id_be, 2);

    sendto(ctx->local_fd, (const void*)buf_recv, msg_size, 0,
           (const struct sockaddr*)&client_addr, sizeof(client_addr));

    if (debug_mode) {
        l = REMOTE_RECEIVE_SENT_TO_CLIENT;
        uint64_t pl = (EVENT_MASK & ((uint64_t)l << 48)) |
            (THREAD_MASK & ((uint64_t)log_thread_id << 32));
        log_write(pl);
    }
    id_map_erase(new_id);

    if (g_cache != NULL) {
        if (debug_mode) {
            l = REMOTE_RECEIVE_HAS_GLOBAL_CACHE;
            uint64_t pl = (EVENT_MASK & ((uint64_t)l << 48)) |
                (THREAD_MASK & ((uint64_t)log_thread_id << 32));
            log_write(pl);
        }
        dns_message_t msg;
        memset(&msg, 0, sizeof(msg));
        dns_message_decode(&msg, buf_recv, msg_size);
        cache_answers_from_msg(&msg);
        dns_message_free(&msg);
    } else if (g_cache == NULL && debug_mode) {
        l = REMOTE_RECEIVE_NO_GLOBAL_CACHE;
        uint64_t pl = (EVENT_MASK & ((uint64_t)l << 48)) |
            (THREAD_MASK & ((uint64_t)log_thread_id << 32));
        log_write(pl);
    }
    return 1; /* successfully processed one datagram */
}

int local_receive(worker_ctx_t* ctx) {
    log_event_t l;
    uint8_t buf_recv[BUFFER_SIZE];
    uint8_t buf_to_send[BUFFER_SIZE];

    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    memset(&client_addr, 0, sizeof(client_addr));

    int msg_size = recvfrom(ctx->local_fd, (void*)buf_recv, sizeof(buf_recv), 0,
                            (struct sockaddr*)&client_addr, &client_len);
    if (msg_size < 0) {
        /* EAGAIN / EWOULDBLOCK: no more packets in the kernel buffer. */
        return 0;
    }
    if (msg_size == 0) {
        if (debug_mode) {
            l = LOCAL_RECEIVE_RECVFROM_FAILED;
            uint64_t pl = (EVENT_MASK & ((uint64_t)l << 48)) |
                (THREAD_MASK & ((uint64_t)log_thread_id << 32));
            pl |= (INFO_MASK & ntohl(client_addr.sin_addr.s_addr));
            log_write(pl);
        }
        return 1; /* consumed one (empty) datagram, keep draining */
    }

    /* ------------------------------------------------------------------
     * Fast path: try to satisfy the query from cache without any heap
     * allocation.  Falls through to the full decode path on miss.
     * ------------------------------------------------------------------ */
    if (g_cache != NULL && msg_size >= 12) {
        dns_query_fast_t qf;
        if (dns_query_decode_fast(buf_recv, msg_size, &qf) && qf.q_type == DNS_TYPE_A) {
            if (debug_mode) {
                l = LOCAL_RECEIVE_CAN_RESOLVE_LOCALLY;
                uint64_t pl = (EVENT_MASK & ((uint64_t)l << 48)) |
                    (THREAD_MASK & ((uint64_t)log_thread_id << 32));
                log_write(pl);
            }
            uint32_t ip = 0;
            if (cache_find(g_cache, qf.q_name, &ip)) {
                if (debug_mode) {
                    l = LOCAL_RECEIVE_HIT_CACHE;
                    uint64_t pl = (EVENT_MASK & ((uint64_t)l << 48)) |
                        (THREAD_MASK & ((uint64_t)log_thread_id << 32));
                    pl |= (INFO_MASK & ip);
                    log_write(pl);
                }
                uint8_t ip_addr[4];
                ip_addr[0] = (uint8_t)((ip >> 24) & 0xFF);
                ip_addr[1] = (uint8_t)((ip >> 16) & 0xFF);
                ip_addr[2] = (uint8_t)((ip >> 8) & 0xFF);
                ip_addr[3] = (uint8_t)(ip & 0xFF);

                int nxdomain = (ip == 0);
                int reply_size = dns_reply_encode_fast(&qf, ip_addr, nxdomain, buf_to_send);
                if (reply_size > 0) {
                    sendto(ctx->local_fd, (const void*)buf_to_send, reply_size, 0,
                           (const struct sockaddr*)&client_addr, client_len);
                } else {
                    if (debug_mode) {
                        l = LOCAL_RECEIVE_REPLY_SIZE_ERROR;
                        uint64_t pl = (EVENT_MASK & ((uint64_t)l << 48)) |
                            (THREAD_MASK & ((uint64_t)log_thread_id << 32));
                        log_write(pl);
                    }
                }
                if (debug_mode) {
                    l = LOCAL_RECEIVE_DNS_MESSAGE_FREE_SUCCESS;
                    uint64_t pl = (EVENT_MASK & ((uint64_t)l << 48)) |
                        (THREAD_MASK & ((uint64_t)log_thread_id << 32));
                    log_write(pl);
                }
                return 1;
            }
        }
    }

    /* ------------------------------------------------------------------
     * Slow path: full decode (cache miss, non-A query, or fast-decode
     * failure).  Forward the query to the upstream resolver.
     * ------------------------------------------------------------------ */
    if (debug_mode) {
        l = LOCAL_RECEIVE_CANNOT_HIT_CACHE;
        uint64_t pl = (EVENT_MASK & ((uint64_t)l << 48)) |
            (THREAD_MASK & ((uint64_t)log_thread_id << 32));
        log_write(pl);
    }

    dns_message_t msg;
    memset(&msg, 0, sizeof(msg));
    dns_message_decode(&msg, buf_recv, msg_size);

    if (msg.header == NULL) {
        if (debug_mode) {
            l = LOCAL_RECEIVE_DECODE_NULL_HEADER;
            uint64_t pl = (EVENT_MASK & ((uint64_t)l << 48)) |
                (THREAD_MASK & ((uint64_t)log_thread_id << 32));
            log_write(pl);
        }
        dns_message_free(&msg);
        return 1; /* consumed one datagram */
    }

    uint16_t orig_id = msg.header->id;

    uint16_t new_id = 0;
    if (!id_map_insert(orig_id, &client_addr, &new_id)) {  // no empty slot, drop
        if (debug_mode) {
            l = LOCAL_RECEIVE_NO_EMPTY_SLOT_DROP;
            uint64_t pl = (EVENT_MASK & ((uint64_t)l << 48)) |
                (THREAD_MASK & ((uint64_t)log_thread_id << 32));
            log_write(pl);
        }
        dns_message_free(&msg);
        return 1;
    }

    uint16_t new_id_be = htons(new_id);
    memcpy(buf_recv, &new_id_be, 2);

    sendto(ctx->remote_fd, (const void*)buf_recv, msg_size, 0,
           (const struct sockaddr*)&ctx->remote_addr, sizeof(ctx->remote_addr));

    if (debug_mode) {
        l = LOCAL_RECEIVE_SENT_TO_UPSTREAM;
        uint64_t pl = (EVENT_MASK & ((uint64_t)l << 48)) |
            (THREAD_MASK & ((uint64_t)log_thread_id << 32));
        log_write(pl);
    }
    dns_message_free(&msg);
    return 1;
}
