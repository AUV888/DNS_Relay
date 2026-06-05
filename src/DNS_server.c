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
            // Timeout: run periodic housekeeping, then go back to sleep
            if (debug_mode) {
                l = BLOCK_MODE_TIMEOUT;
                uint64_t pl = EVENT_MASK & ((uint64_t)l << 48);
                log_write(pl);
            }
            id_map_sweep_timeout();
            continue;
        }

        // Dispatch ready file descriptors
        if (FD_ISSET(local_socket_fd, &rset)) {
            if (debug_mode) {
                l = BLOCK_MODE_LOCAL_RECEIVE;
                uint64_t pl = EVENT_MASK & ((uint64_t)l << 48);
                log_write(pl);
            }
            local_receive();
        }
        if (FD_ISSET(remote_socket_fd, &rset)) {
            if (debug_mode) {
                l = BLOCK_MODE_REMOTE_RECEIVE;
                uint64_t pl = EVENT_MASK & ((uint64_t)l << 48);
                log_write(pl);
            }
            remote_receive();
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
        uint64_t pl = EVENT_MASK & ((uint64_t)l << 48);
        log_write(pl);
    }
}

void remote_receive() {
    uint8_t buf_recv[BUFFER_SIZE];

    log_event_t l;
    struct sockaddr_in upstream_addr;
    socklen_t upstream_len = sizeof(upstream_addr);

    int msg_size = recvfrom(remote_socket_fd, (void*)buf_recv, sizeof(buf_recv), 0,
                            (struct sockaddr*)&upstream_addr, &upstream_len);
    if (msg_size < 2) {
        if (debug_mode) {
            l = REMOTE_RECEIVE_MSG_SIZE_ERR;
            uint64_t pl = EVENT_MASK & ((uint64_t)l << 48);
            log_write(pl);
        }
        return;
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
        return;
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
        dns_message_t msg;
        memset(&msg, 0, sizeof(msg));
        dns_message_decode(&msg, buf_recv);
        cache_answers_from_msg(&msg);
        dns_message_free(&msg);
    } else if (g_cache == NULL && debug_mode) {
        l = REMOTE_RECEIVE_NO_GLOBAL_CACHE;
        uint64_t pl = EVENT_MASK & ((uint64_t)l << 48);
        log_write(pl);
    }
}

void local_receive() {
    log_event_t l;
    uint8_t buf_recv[BUFFER_SIZE];
    uint8_t buf_to_send[BUFFER_SIZE];

    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    memset(&client_addr, 0, sizeof(client_addr));

    int msg_size = recvfrom(local_socket_fd, (void*)buf_recv, sizeof(buf_recv), 0,
                            (struct sockaddr*)&client_addr, &client_len);
    if (msg_size <= 0) {
        if (debug_mode) {
            l = LOCAL_RECEIVE_RECVFROM_FAILED;
            uint64_t pl = EVENT_MASK & ((uint64_t)l << 48);
            pl |= (INFO_MASK & ntohl(client_addr.sin_addr.s_addr));
            log_write(pl);
        }
        return;
    }

    dns_message_t msg;
    memset(&msg, 0, sizeof(msg));
    dns_message_decode(&msg, buf_recv);

    if (msg.header == NULL) {
        if (debug_mode) {
            l = LOCAL_RECEIVE_DECODE_NULL_HEADER;
            uint64_t pl = EVENT_MASK & ((uint64_t)l << 48);
            log_write(pl);
        }
        dns_message_free(&msg);
        return;
    }

    // we only cached A record
    int can_resolve_locally = (msg.header->qdcount >= 1) && (msg.question != NULL) &&
                              (msg.question->q_name != NULL) &&
                              (msg.question->q_type == DNS_TYPE_A);

    if (can_resolve_locally && g_cache != NULL) {
        if (debug_mode) {
            l = LOCAL_RECEIVE_CAN_RESOLVE_LOCALLY;
            uint64_t pl = EVENT_MASK & ((uint64_t)l << 48);
            log_write(pl);
        }
        uint32_t ip = 0;
        if (cache_find(g_cache, msg.question->q_name, &ip)) {
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

            dns_resource_record_t* ans =
                (dns_resource_record_t*)malloc(sizeof(dns_resource_record_t));
            if (ans) {
                memset(ans, 0, sizeof(*ans));
                size_t nlen = strlen(msg.question->q_name);
                ans->name = (char*)malloc(nlen + 1);
                if (ans->name) {
                    memcpy(ans->name, msg.question->q_name, nlen + 1);
                } else {
                    if (debug_mode) {
                        l = LOCAL_RECEIVE_ANS_NAME_MALLOC_FAILED;
                        uint64_t pl = EVENT_MASK & ((uint64_t)l << 48);
                        log_write(pl);
                    }
                    return;
                }
                ans->type = DNS_TYPE_A;
                ans->rr_class = DNS_CLASS_IN;
                ans->ttl = 300;
                ans->rd_length = 4;
                memcpy(ans->rd_data.a_record.ip_addr, ip_addr, 4);
                ans->next = NULL;
                msg.answer = ans;

                uint8_t* end = dns_message_encode(&msg, buf_to_send, ip_addr);
                int reply_size = (int)(end - buf_to_send);
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
            } else {
                if (debug_mode) {
                    l = LOCAL_RECEIVE_ANS_MALLOC_FAILED;
                    uint64_t pl = EVENT_MASK & ((uint64_t)l << 48);
                    log_write(pl);
                }
            }
            dns_message_free(&msg);
            if (debug_mode) {
                l = LOCAL_RECEIVE_DNS_MESSAGE_FREE_SUCCESS;
                uint64_t pl = EVENT_MASK & ((uint64_t)l << 48);
                log_write(pl);
            }
            return;
        }
    }

    if (debug_mode) {
        l = LOCAL_RECEIVE_CANNOT_HIT_CACHE;
        uint64_t pl = EVENT_MASK & ((uint64_t)l << 48);
        log_write(pl);
    }

    uint16_t orig_id = msg.header->id;

    uint16_t new_id = 0;
    if (!id_map_insert(orig_id, &client_addr, &new_id)) {  // no empty slot, drop
        if (debug_mode) {
            l = LOCAL_RECEIVE_NO_EMPTY_SLOT_DROP;
            uint64_t pl = EVENT_MASK & ((uint64_t)l << 48);
            log_write(pl);
        }
        dns_message_free(&msg);
        return;
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
    dns_message_free(&msg);
}
