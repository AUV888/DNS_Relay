#include "../include/DNS_server.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
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
char timeout_cnt = 0;

void server_socket_init() {
    log_event_t l;
    sock_addr_len = sizeof(local_addr);

    local_socket_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (local_socket_fd < 0) {
        if (debug_mode) {
            l = LOCAL_SOCKET_FAILED;
            uint64_t pl = EVENT_MASK & ((uint64_t)l << 48);
            log_write(pl);
        }
        exit(EXIT_FAILURE);
    }
    remote_socket_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (remote_socket_fd < 0) {
        if (debug_mode) {
            l = REMOTE_SOCKET_FAILED;
            uint64_t pl = EVENT_MASK & ((uint64_t)l << 48);
            log_write(pl);
        }
        exit(EXIT_FAILURE);
    }

    memset(&local_addr, 0, sizeof(local_addr));
    memset(&remote_addr, 0, sizeof(remote_addr));

    local_addr.sin_family = AF_INET;
    local_addr.sin_addr.s_addr = INADDR_ANY;
    local_addr.sin_port = htons(dns_listen_port);

    remote_addr.sin_family = AF_INET;
    remote_addr.sin_addr.s_addr = inet_addr(dns_server_addr);
    remote_addr.sin_port = htons(dns_upstream_port);

    int opt = 1;
    if (setsockopt(local_socket_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        if (debug_mode) {
            l = SOCKET_OPT_FAILED;
            uint64_t pl = EVENT_MASK & ((uint64_t)l << 48);
            log_write(pl);
        }
        exit(EXIT_FAILURE);
    }

    if (bind(local_socket_fd, (const struct sockaddr*)&local_addr, sizeof(local_addr)) < 0) {
        if (debug_mode) {
            l = SOCKET_BIND_FAILED;
            uint64_t pl = EVENT_MASK & ((uint64_t)l << 48);
            log_write(pl);
        }
        exit(EXIT_FAILURE);
    }

    g_cache = create_hset();
    cache_init(g_cache);

    /* Make both sockets non-blocking so recvfrom returns EAGAIN when the
     * kernel buffer is empty.  This lets the event loop drain all pending
     * packets in a single select() wake-up instead of returning to select
     * after every single datagram. */
    if (set_nonblocking(local_socket_fd) < 0 || set_nonblocking(remote_socket_fd) < 0) {
        if (debug_mode) {
            l = NON_BLOCK_MODE_LOCAL_FSETFL_ERR;
            uint64_t pl = EVENT_MASK & ((uint64_t)l << 48);
            log_write(pl);
        }
        exit(EXIT_FAILURE);
    }

    if (debug_mode) {
        l = SOCKET_INIT_SUCCESS;
        uint64_t pl = EVENT_MASK & ((uint64_t)l << 48);
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
        uint64_t pl = EVENT_MASK & ((uint64_t)l << 48);
        log_write(pl);
    }
}

void server_mode_blocking_set() {
    log_event_t l;
    if (debug_mode) {
        l = BLOCK_MODE_START;
        uint64_t pl = EVENT_MASK & ((uint64_t)l << 48);
        log_write(pl);
    }
    int maxfd = (local_socket_fd > remote_socket_fd ? local_socket_fd : remote_socket_fd) + 1;

    while (1) {
        if (g_shutdown) {
            return;
        }
        fd_set rset;
        FD_ZERO(&rset);
        FD_SET(local_socket_fd, &rset);
        FD_SET(remote_socket_fd, &rset);

        /* Wake up at least once per second so we can run housekeeping. */
        struct timeval tv = {1, 0};
        int n = select(maxfd, &rset, NULL, NULL, &tv);

        if (n < 0) {
            if (errno == EINTR) {
                if (debug_mode) {
                    l = BLOCK_MODE_ERRNO_EINTR;
                    uint64_t pl = EVENT_MASK & ((uint64_t)l << 48);
                    log_write(pl);
                }
                continue;  // interrupted by signal, retry
            }
            if (debug_mode) {
                l = BLOCK_MODE_ERRNO_SELECT;
                uint64_t pl = EVENT_MASK & ((uint64_t)l << 48);
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
                    l = BLOCK_MODE_TIMEOUT;
                    uint64_t pl = EVENT_MASK & ((uint64_t)l << 48);
                    log_write(pl);
                    timeout_cnt = 0;
                }
            }
            id_map_sweep_timeout();
            continue;
        }

        /* Drain all pending packets from each ready socket so that the
         * kernel buffer never builds up across select() calls. */
        if (FD_ISSET(local_socket_fd, &rset)) {
            while (1) {
                if (debug_mode) {
                    l = BLOCK_MODE_LOCAL_RECEIVE;
                    uint64_t pl = EVENT_MASK & ((uint64_t)l << 48);
                    log_write(pl);
                }
                int local = local_receive();
                if (debug_mode) {
                    l = BLOCK_MODE_LOCAL_RECEIVE_NUM;
                    uint64_t pl =
                        (EVENT_MASK & ((uint64_t)l << 48)) | (INFO_MASK & (uint64_t)local);
                    log_write(pl);
                }
                if (local == 0)
                    break;
            }
        }
        if (FD_ISSET(remote_socket_fd, &rset)) {
            while (1) {
                if (debug_mode) {
                    l = BLOCK_MODE_REMOTE_RECEIVE;
                    uint64_t pl = EVENT_MASK & ((uint64_t)l << 48);
                    log_write(pl);
                }
                int remote = remote_receive();
                if (debug_mode) {
                    l = BLOCK_MODE_REMOTE_RECEIVE_NUM;
                    uint64_t pl =
                        (EVENT_MASK & ((uint64_t)l << 48)) | (INFO_MASK & (uint64_t)remote);
                    log_write(pl);
                }
                if (remote == 0)
                    break;
            }
        }
    }
}

void server_mode_non_blocking_set() {
    int flags;

    log_event_t l;
    if (debug_mode) {
        l = NON_BLOCK_MODE_START;
        uint64_t pl = EVENT_MASK & ((uint64_t)l << 48);
        log_write(pl);
    }
    flags = fcntl(local_socket_fd, F_GETFL, 0);  // get file status flags
    if (flags < 0) {
        if (debug_mode) {
            l = NON_BLOCK_MODE_LOCAL_FGETFL_ERR;
            uint64_t pl = EVENT_MASK & ((uint64_t)l << 48);
            log_write(pl);
        }
        return;
    }
    if (fcntl(local_socket_fd, F_SETFL, flags | O_NONBLOCK) < 0) {  // set file status flags
        if (debug_mode) {
            l = NON_BLOCK_MODE_LOCAL_FSETFL_ERR;
            uint64_t pl = EVENT_MASK & ((uint64_t)l << 48);
            log_write(pl);
        }
    }

    flags = fcntl(remote_socket_fd, F_GETFL, 0);
    if (flags < 0) {
        if (debug_mode) {
            l = NON_BLOCK_MODE_REMOTE_FGETFL_ERR;
            uint64_t pl = EVENT_MASK & ((uint64_t)l << 48);
            log_write(pl);
        }
        return;
    }
    if (fcntl(remote_socket_fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        if (debug_mode) {
            l = NON_BLOCK_MODE_REMOTE_FSETFL_ERR;
            uint64_t pl = EVENT_MASK & ((uint64_t)l << 48);
            log_write(pl);
        }
    }

    time_t last_sweep = time(NULL);

    while (1) {
        if (g_shutdown) {
            return;
        }
        local_receive();
        if (debug_mode) {
            l = NON_BLOCK_MODE_LOCAL_RECEIVE;
            uint64_t pl = EVENT_MASK & ((uint64_t)l << 48);
            log_write(pl);
        }
        remote_receive();
        if (debug_mode) {
            l = NON_BLOCK_MODE_REMOTE_RECEIVE;
            uint64_t pl = EVENT_MASK & ((uint64_t)l << 48);
            log_write(pl);
        }
        time_t now = time(NULL);
        if (now - last_sweep >= 1) {
            if (debug_mode) {
                l = NON_BLOCK_SWEEP;
                uint64_t pl = EVENT_MASK & ((uint64_t)l << 48);
                log_write(pl);
            }
            id_map_sweep_timeout();
            last_sweep = now;
        }
    }
}

static inline void cache_answers_from_msg(uint32_t* ipv4, uint32_t* ttl, char* name) {
    if (!g_cache)
        return;
    cache_insert(g_cache, name, *ipv4, *ttl);
    if (debug_mode) {
        log_event_t l = REMOTE_RECEIVE_CACHED_ANSWER_SUCCESS;
        uint64_t pl = EVENT_MASK & ((uint64_t)l << 48);
        log_write(pl);
    }
}

int remote_receive() {
    uint8_t buf_recv[BUFFER_SIZE];

    log_event_t l;
    struct sockaddr_in upstream_addr;
    socklen_t upstream_len = sizeof(upstream_addr);

    int msg_size = recvfrom(remote_socket_fd, (void*)buf_recv, sizeof(buf_recv), 0,
                            (struct sockaddr*)&upstream_addr, &upstream_len);
    if (msg_size < 0) {
        /* EAGAIN / EWOULDBLOCK means the buffer is empty — stop draining. */
        return 0;
    }
    if (msg_size < 12) {
        if (debug_mode) {
            l = REMOTE_RECEIVE_MSG_SIZE_ERR;
            uint64_t pl = EVENT_MASK & ((uint64_t)l << 48);
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
            uint64_t pl = EVENT_MASK & ((uint64_t)l << 48);
            log_write(pl);
        }
        return 1; /* consumed one datagram (dropped), keep draining */
    }

    uint16_t orig_id_be = htons(orig_id);
    memcpy(buf_recv, &orig_id_be, 2);

    sendto(local_socket_fd, (const void*)buf_recv, msg_size, 0,
           (const struct sockaddr*)&client_addr, sizeof(client_addr));

    if (debug_mode) {
        l = REMOTE_RECEIVE_SENT_TO_CLIENT;
        uint64_t pl = EVENT_MASK & ((uint64_t)l << 48);
        log_write(pl);
    }
    id_map_erase(new_id);

    if (g_cache != NULL) {
        if (debug_mode) {
            l = REMOTE_RECEIVE_HAS_GLOBAL_CACHE;
            uint64_t pl = EVENT_MASK & ((uint64_t)l << 48);
            log_write(pl);
        }
        char name[DNS_RR_NAME_MAX_SIZE] = {0};
        uint32_t ipv4 = 0, ttl = 0;
        char is_A_type = 0;
        uint8_t* buf = buf_recv + 12;
        uint8_t* start = buf_recv;
        buf = get_dns_question(buf, start, start + msg_size);
        if (buf != NULL) {
            buf = get_dns_answer(buf, start, start + msg_size, name, &ipv4, &is_A_type, &ttl);
        }
        if (is_A_type) {
            cache_answers_from_msg(&ipv4, &ttl, name);
        }

    } else if (g_cache == NULL && debug_mode) {
        l = REMOTE_RECEIVE_NO_GLOBAL_CACHE;
        uint64_t pl = EVENT_MASK & ((uint64_t)l << 48);
        log_write(pl);
    }
    return 1; /* successfully processed one datagram */
}

int local_receive() {
    log_event_t l;
    uint8_t buf_recv[BUFFER_SIZE];
    uint8_t buf_to_send[BUFFER_SIZE];

    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    memset(&client_addr, 0, sizeof(client_addr));

    int msg_size = recvfrom(local_socket_fd, (void*)buf_recv, sizeof(buf_recv), 0,
                            (struct sockaddr*)&client_addr, &client_len);
    if (msg_size < 0) {
        /* EAGAIN / EWOULDBLOCK: no more packets in the kernel buffer. */
        return 0;
    }
    if (msg_size == 0) {
        if (debug_mode) {
            l = LOCAL_RECEIVE_RECVFROM_FAILED;
            uint64_t pl = EVENT_MASK & ((uint64_t)l << 48);
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
                uint64_t pl = EVENT_MASK & ((uint64_t)l << 48);
                log_write(pl);
            }
            uint32_t ip = 0;
            if (cache_find(g_cache, qf.q_name, &ip)) {
                if (debug_mode) {
                    l = LOCAL_RECEIVE_HIT_CACHE;
                    uint64_t pl = EVENT_MASK & ((uint64_t)l << 48);
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
                    sendto(local_socket_fd, (const void*)buf_to_send, reply_size, 0,
                           (const struct sockaddr*)&client_addr, client_len);
                } else {
                    if (debug_mode) {
                        l = LOCAL_RECEIVE_REPLY_SIZE_ERROR;
                        uint64_t pl = EVENT_MASK & ((uint64_t)l << 48);
                        log_write(pl);
                    }
                }
                if (debug_mode) {
                    l = LOCAL_RECEIVE_DNS_MESSAGE_FREE_SUCCESS;
                    uint64_t pl = EVENT_MASK & ((uint64_t)l << 48);
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
        uint64_t pl = EVENT_MASK & ((uint64_t)l << 48);
        log_write(pl);
    }

    if (msg_size < 12) {
        if (debug_mode) {
            l = LOCAL_RECEIVE_DECODE_NULL_HEADER;
            uint64_t pl = EVENT_MASK & ((uint64_t)l << 48);
            log_write(pl);
        }
        return 1; /* consumed one datagram */
    }

    uint16_t orig_id = (buf_recv[0] << 8) | (buf_recv[1]);

    uint16_t new_id = 0;
    if (!id_map_insert(orig_id, &client_addr, &new_id)) {  // no empty slot, drop
        if (debug_mode) {
            l = LOCAL_RECEIVE_NO_EMPTY_SLOT_DROP;
            uint64_t pl = EVENT_MASK & ((uint64_t)l << 48);
            log_write(pl);
        }
        return 1;
    }

    uint16_t new_id_be = htons(new_id);
    memcpy(buf_recv, &new_id_be, 2);

    sendto(remote_socket_fd, (const void*)buf_recv, msg_size, 0,
           (const struct sockaddr*)&remote_addr, sizeof(remote_addr));

    if (debug_mode) {
        l = LOCAL_RECEIVE_SENT_TO_UPSTREAM;
        uint64_t pl = EVENT_MASK & ((uint64_t)l << 48);
        log_write(pl);
    }
    return 1;
}
