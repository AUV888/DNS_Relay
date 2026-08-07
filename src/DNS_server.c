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

    /* ------------------------------------------------------------------
     * The listening socket is shared by all modes and always created
     * here.  In multi-threaded blocking mode the dispatcher thread is
     * the ONLY thread that recvfrom()s it and round-robins every query
     * to one of the workers; in the legacy non-blocking mode the single
     * event loop reads it directly.
     * ------------------------------------------------------------------ */
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

    /* Non-blocking: the dispatcher (or the legacy loop) busy-polls on
     * it and treats EAGAIN as "kernel buffer empty, spin on". */
    if (set_nonblocking(local_socket_fd) < 0) {
        if (debug_mode) {
            l = NON_BLOCK_MODE_LOCAL_FSETFL_ERR;
            uint64_t pl = (EVENT_MASK & ((uint64_t)l << 48)) |
                (THREAD_MASK & ((uint64_t)log_thread_id << 32));
            log_write(pl);
        }
        exit(EXIT_FAILURE);
    }

    if (blocking_mode) {
        /* Multi-threaded path: no global upstream socket here.  Every
         * worker creates its own remote socket in worker_main(), so an
         * upstream reply always comes back to the very worker that
         * forwarded the query. */
        if (debug_mode) {
            l = SOCKET_INIT_SUCCESS;
            uint64_t pl = (EVENT_MASK & ((uint64_t)l << 48)) |
                (THREAD_MASK & ((uint64_t)log_thread_id << 32));
            log_write(pl);
        }
        return;
    }

    /* Legacy single-threaded (non-blocking) path also gets a global
     * upstream socket. */
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
    if (set_nonblocking(remote_socket_fd) < 0) {
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
 * Multi-threaded blocking mode: dispatcher + round-robin workers.
 *
 * One dispatcher thread is the sole reader of the shared listening
 * socket.  For every incoming query it does:
 *
 *     i = cnt++ % worker_thread_cnt
 *     copy the packet into worker i's SPSC ring
 *
 * Each worker busy-polls its own ring, processes queries (cache hit →
 * reply through the shared listening socket; miss → forward through its
 * private upstream socket), and drains upstream replies from that
 * private socket.  The rings are single-producer / single-consumer, so
 * they need no locks — just two atomic counters with acquire/release
 * ordering.
 * ----------------------------------------------------------------------- */

#define RING_SIZE 512 /* slots per worker; must be a power of two */

typedef struct ring_slot {
    uint8_t buf[BUFFER_SIZE];
    int msg_size;
    struct sockaddr_in client_addr;
    socklen_t client_len;
} ring_slot_t;

typedef struct pkt_ring {
    _Alignas(64) _Atomic uint64_t head; /* advanced by the dispatcher */
    _Alignas(64) _Atomic uint64_t tail; /* advanced by the worker */
    ring_slot_t slots[RING_SIZE];
} pkt_ring_t;

/* One ring per worker; allocated in server_mode_blocking_set(). */
static pkt_ring_t* pkt_rings = NULL;

/* Round-robin counter used by the dispatcher to pick the target worker. */
static _Atomic uint64_t rr_cnt = 0;

/* Queries dropped because the target worker's ring was full.  Printed
 * once on shutdown; UDP semantics make dropping a legal overload policy. */
static _Atomic uint64_t dispatch_drop_cnt = 0;

/* Push one packet into a ring.  Returns 0 (drop) when the ring is full.
 * Only the dispatcher may call this for a given ring. */
static int ring_push(pkt_ring_t* r, const uint8_t* buf, int len,
                     const struct sockaddr_in* cli, socklen_t clen) {
    uint64_t head = atomic_load_explicit(&r->head, memory_order_relaxed);
    uint64_t tail = atomic_load_explicit(&r->tail, memory_order_acquire);
    if (head - tail >= RING_SIZE)
        return 0; /* full */

    ring_slot_t* s = &r->slots[head & (RING_SIZE - 1)];
    memcpy(s->buf, buf, (size_t)len);
    s->msg_size = len;
    s->client_addr = *cli;
    s->client_len = clen;

    /* Release: the slot contents above become visible to the worker
     * together with the new head value. */
    atomic_store_explicit(&r->head, head + 1, memory_order_release);
    return 1;
}

/* Peek the next unconsumed slot.  Returns 0 when the ring is empty.
 * Only the owning worker may call this for a given ring. */
static int ring_pop(pkt_ring_t* r, ring_slot_t** out) {
    uint64_t tail = atomic_load_explicit(&r->tail, memory_order_relaxed);
    uint64_t head = atomic_load_explicit(&r->head, memory_order_acquire);
    if (tail == head)
        return 0; /* empty */
    *out = &r->slots[tail & (RING_SIZE - 1)];
    return 1;
}

/* Advance the consumer cursor after the slot has been fully processed.
 * Release: the dispatcher may not overwrite the slot before it observes
 * this new tail value. */
static void ring_pop_commit(pkt_ring_t* r) {
    uint64_t tail = atomic_load_explicit(&r->tail, memory_order_relaxed);
    atomic_store_explicit(&r->tail, tail + 1, memory_order_release);
}

/* The dispatcher: sole recvfrom() site on the shared listening socket.
 * arg carries the worker count. */
static void* dispatcher_main(void* arg) {
    long n = (long)(intptr_t)arg;

    /* Own log identity (printed as [disp] by the Parser). */
    log_thread_id = LOG_THREAD_ID_DISPATCHER;

    uint8_t buf[BUFFER_SIZE];
    struct sockaddr_in client_addr;

    while (!atomic_load(&g_shutdown)) {
        socklen_t client_len = sizeof(client_addr);
        int msg_size = recvfrom(local_socket_fd, (void*)buf, sizeof(buf), 0,
                                (struct sockaddr*)&client_addr, &client_len);
        if (msg_size <= 0) {
            /* EAGAIN/EWOULDBLOCK: kernel buffer empty — keep polling.
             * Empty datagrams (== 0) and transient UDP errors are
             * discarded here, same net effect as the old per-receive
             * error path. */
            continue;
        }
        uint64_t i =
            atomic_fetch_add_explicit(&rr_cnt, 1, memory_order_relaxed) % (uint64_t)n;
        if (!ring_push(&pkt_rings[i], buf, msg_size, &client_addr, client_len)) {
            atomic_fetch_add_explicit(&dispatch_drop_cnt, 1, memory_order_relaxed);
        }
    }
    return NULL;
}

/* One worker: drain its own ring, handle its own upstream socket. */
static void* worker_main(void* arg) {
    worker_ctx_t* ctx = (worker_ctx_t*)arg;

    /* Tag every log record this worker writes with its 0-based index.
     * Must happen before the first log_write() of this thread. */
    log_thread_id = (uint16_t)ctx->tid;

    pkt_ring_t* ring = &pkt_rings[ctx->tid];

    /* Private upstream socket: replies from the upstream server match
     * this socket's 4-tuple, so they always come back to the very
     * worker that forwarded the query. */
    ctx->remote_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (ctx->remote_fd < 0) {
        if (debug_mode) {
            log_event_t l = REMOTE_SOCKET_FAILED;
            uint64_t pl = (EVENT_MASK & ((uint64_t)l << 48)) |
                (THREAD_MASK & ((uint64_t)log_thread_id << 32));
            log_write(pl);
        }
        return NULL;
    }
    if (set_nonblocking(ctx->remote_fd) < 0) {
        if (debug_mode) {
            log_event_t l = NON_BLOCK_MODE_LOCAL_FSETFL_ERR;
            uint64_t pl = (EVENT_MASK & ((uint64_t)l << 48)) |
                (THREAD_MASK & ((uint64_t)log_thread_id << 32));
            log_write(pl);
        }
        close(ctx->remote_fd);
        ctx->remote_fd = -1;
        return NULL;
    }

    time_t last_sweep = time(NULL);

    while (!atomic_load(&g_shutdown)) {
        /* Consume every query the dispatcher has queued for us. */
        ring_slot_t* slot;
        while (ring_pop(ring, &slot)) {
            local_process_packet(ctx, slot->buf, slot->msg_size,
                                 &slot->client_addr, slot->client_len);
            ring_pop_commit(ring);
        }

        /* Upstream answers arrive on our private socket. */
        remote_receive(ctx);

        /* ID-map housekeeping: worker 0 only, at most once per second. */
        if (ctx->tid == 0) {
            time_t now = time(NULL);
            if (now - last_sweep >= 1) {
                id_map_sweep_timeout();
                last_sweep = now;
            }
        }
    }

    /* Do NOT close ctx->local_fd: the listening socket is shared and is
     * closed by server_socket_close() after all threads have joined. */
    close(ctx->remote_fd);
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

    /* One SPSC ring per worker.  aligned_alloc(64, ...) keeps the
     * head/tail counters of neighbouring rings on separate cache lines
     * (the struct size is a multiple of 64 thanks to _Alignas, which
     * aligned_alloc requires). */
    pkt_rings = (pkt_ring_t*)aligned_alloc(64, (size_t)n * sizeof(pkt_ring_t));
    pthread_t* tids = (pthread_t*)malloc((size_t)n * sizeof(pthread_t));
    worker_ctx_t* ctxs = (worker_ctx_t*)malloc((size_t)n * sizeof(worker_ctx_t));
    if (!pkt_rings || !tids || !ctxs) {
        free(pkt_rings);
        pkt_rings = NULL;
        free(tids);
        free(ctxs);
        return;
    }
    memset(pkt_rings, 0, (size_t)n * sizeof(pkt_ring_t));

    long started = 0;
    for (long i = 0; i < n; i++) {
        ctxs[i].tid = (int)i;
        ctxs[i].local_fd = local_socket_fd; /* shared listening socket */
        ctxs[i].remote_fd = -1;
        ctxs[i].remote_addr = remote_addr;  /* read-only snapshot */
        if (pthread_create(&tids[i], NULL, worker_main, &ctxs[i]) != 0) {
            fprintf(stderr, "failed to start worker thread %ld\n", i);
            break;
        }
        started++;
    }

    /* The dispatcher feeds the workers; without it no query can ever
     * arrive, so on failure shut everything down again. */
    pthread_t disp_tid;
    int disp_started = 0;
    if (started > 0) {
        if (pthread_create(&disp_tid, NULL, dispatcher_main, (void*)(intptr_t)started) != 0) {
            fprintf(stderr, "failed to start dispatcher thread\n");
            atomic_store(&g_shutdown, 1);
        } else {
            disp_started = 1;
        }
    }

    /* Stop the producer first, then the consumers.  Every thread exits
     * on its own once it observes g_shutdown (within one busy-loop
     * iteration).  After the joins, no thread can touch the shared
     * structures anymore. */
    if (disp_started) {
        pthread_join(disp_tid, NULL);
    }
    for (long i = 0; i < started; i++) {
        pthread_join(tids[i], NULL);
    }

    uint64_t drops = atomic_load(&dispatch_drop_cnt);
    if (drops > 0) {
        fprintf(stderr, "dispatcher: %llu queries dropped (worker rings full)\n",
                (unsigned long long)drops);
    }

    free(pkt_rings);
    pkt_rings = NULL;
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

/* -----------------------------------------------------------------------
 * local_process_packet — handle one already-received client query.
 *
 * Shared by both packet sources:
 *   - local_receive()            legacy non-blocking mode, recvfrom there
 *   - the multi-threaded workers the dispatcher recvfrom'd the packet
 *     and queued it, the worker pops it from its SPSC ring
 *
 * buf_recv must be writable: the slow path rewrites the DNS transaction
 * ID in place before forwarding to the upstream server.
 * Returns 1 once the datagram has been consumed (answered or forwarded).
 * ----------------------------------------------------------------------- */
int local_process_packet(worker_ctx_t* ctx, uint8_t* buf_recv, int msg_size,
                         const struct sockaddr_in* client_addr, socklen_t client_len) {
    log_event_t l;
    uint8_t buf_to_send[BUFFER_SIZE];

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
                           (const struct sockaddr*)client_addr, client_len);
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
    if (!id_map_insert(orig_id, client_addr, &new_id)) {  // no empty slot, drop
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

/* recvfrom wrapper used ONLY by the legacy single-threaded non-blocking
 * mode.  In the multi-threaded blocking mode the dispatcher owns the
 * recvfrom() on the shared listening socket and workers consume packets
 * from their rings via local_process_packet(). */
int local_receive(worker_ctx_t* ctx) {
    uint8_t buf_recv[BUFFER_SIZE];
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
            log_event_t l = LOCAL_RECEIVE_RECVFROM_FAILED;
            uint64_t pl = (EVENT_MASK & ((uint64_t)l << 48)) |
                (THREAD_MASK & ((uint64_t)log_thread_id << 32));
            pl |= (INFO_MASK & ntohl(client_addr.sin_addr.s_addr));
            log_write(pl);
        }
        return 1; /* consumed one (empty) datagram */
    }
    return local_process_packet(ctx, buf_recv, msg_size, &client_addr, client_len);
}
