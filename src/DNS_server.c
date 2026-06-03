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
#include "../include/DNS_id.h"
#include "../include/DNS_struct.h"

int local_socket_fd = -1;
int remote_socket_fd = -1;
int sock_addr_len;

struct sockaddr_in local_addr;
struct sockaddr_in remote_addr;


cache_set* g_cache;

void server_socket_init() {
    sock_addr_len = sizeof(local_addr);

    local_socket_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (local_socket_fd < 0) {
        perror("local socket failed");
    }
    remote_socket_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (remote_socket_fd < 0) {
        perror("remote socket failed");
    }

    memset(&local_addr, 0, sizeof(local_addr));
    memset(&remote_addr, 0, sizeof(remote_addr));

    local_addr.sin_family = AF_INET;
    local_addr.sin_addr.s_addr = INADDR_ANY;
    local_addr.sin_port = htons(DNS_PORT);

    remote_addr.sin_family = AF_INET;
    remote_addr.sin_addr.s_addr = inet_addr(dns_server_addr);
    remote_addr.sin_port = htons(DNS_PORT);

    int opt = 1;
    if (setsockopt(local_socket_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt SO_REUSEADDR failed");
    }

    if (bind(local_socket_fd, (const struct sockaddr*)&local_addr, sizeof(local_addr)) < 0) {
        perror("bind failed");
    }

    g_cache = create_hset();
    cache_init(g_cache);

    printf("Server socket ready.\n");
}

void server_socket_close() {
    if (local_socket_fd != -1) {
        close(local_socket_fd);
        local_socket_fd = -1;
    }
    if (remote_socket_fd != -1) {
        close(remote_socket_fd);
        remote_socket_fd = -1;
    }
}

void server_mode_blocking_set() {
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
            if (errno == EINTR)
                continue;  // interrupted by signal, retry
            perror("select");
            break;
        }

        if (n == 0) {
            // Timeout: run periodic housekeeping, then go back to sleep
            id_map_sweep_timeout();
            continue;
        }

        // Dispatch ready file descriptors
        if (FD_ISSET(local_socket_fd, &rset))
            local_receive();
        if (FD_ISSET(remote_socket_fd, &rset))
            remote_receive();
    }
}

void server_mode_non_blocking_set() {
    int flags;

    flags = fcntl(local_socket_fd, F_GETFL, 0);  // get file status flags
    if (flags < 0) {
        perror("fcntl F_GETFL local");
        return;
    }
    if (fcntl(local_socket_fd, F_SETFL, flags | O_NONBLOCK) < 0)  // set file status flags
        perror("fcntl F_SETFL local");

    flags = fcntl(remote_socket_fd, F_GETFL, 0);
    if (flags < 0) {
        perror("fcntl F_GETFL remote");
        return;
    }
    if (fcntl(remote_socket_fd, F_SETFL, flags | O_NONBLOCK) < 0)
        perror("fcntl F_SETFL remote");

    time_t last_sweep = time(NULL);

    while (1) {
        local_receive();
        remote_receive();

        time_t now = time(NULL);
        if (now - last_sweep >= 1) {
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
}

void remote_receive() {
    uint8_t buf_recv[BUFFER_SIZE];

    struct sockaddr_in upstream_addr;
    socklen_t upstream_len = sizeof(upstream_addr);

    int msg_size = recvfrom(remote_socket_fd, (void*)buf_recv, sizeof(buf_recv), 0,
                            (struct sockaddr*)&upstream_addr, &upstream_len);
    if (msg_size < 2)
        return;

    uint16_t new_id_be;
    memcpy(&new_id_be, buf_recv, 2);
    uint16_t new_id = ntohs(new_id_be);

    uint16_t orig_id = 0;
    struct sockaddr_in client_addr;
    if (!id_map_find(new_id, &orig_id, &client_addr)) {  // no original id, drop
        return;
    }

    uint16_t orig_id_be = htons(orig_id);
    memcpy(buf_recv, &orig_id_be, 2);

    sendto(local_socket_fd, (const void*)buf_recv, msg_size, 0,
           (const struct sockaddr*)&client_addr, sizeof(client_addr));

    id_map_erase(new_id);

    if (g_cache != NULL) {
        dns_message_t msg;
        memset(&msg, 0, sizeof(msg));
        dns_message_decode(&msg, buf_recv);
        cache_answers_from_msg(&msg);
        dns_message_free(&msg);
    }
}

void local_receive() {
    uint8_t buf_recv[BUFFER_SIZE];
    uint8_t buf_to_send[BUFFER_SIZE];

    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    memset(&client_addr, 0, sizeof(client_addr));

    int msg_size = recvfrom(local_socket_fd, (void*)buf_recv, sizeof(buf_recv), 0,
                            (struct sockaddr*)&client_addr, &client_len);
    if (msg_size <= 0)
        return;

    dns_message_t msg;
    memset(&msg, 0, sizeof(msg));
    dns_message_decode(&msg, buf_recv);

    if (msg.header == NULL) {
        dns_message_free(&msg);
        return;
    }

    // we only cached A record
    int can_resolve_locally = (msg.header->qdcount >= 1) && (msg.question != NULL) &&
                              (msg.question->q_name != NULL) &&
                              (msg.question->q_type == DNS_TYPE_A);

    if (can_resolve_locally && g_cache != NULL) {
        uint32_t ip = 0;
        if (cache_find(g_cache, msg.question->q_name, &ip)) {
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
                if (ans->name)
                    memcpy(ans->name, msg.question->q_name, nlen + 1);
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
                }
            }
            dns_message_free(&msg);
            return;
        }
    }

    uint16_t orig_id = msg.header->id;

    uint16_t new_id = 0;
    if (!id_map_insert(orig_id, &client_addr, &new_id)) {  // no empty slot, drop
        dns_message_free(&msg);
        return;
    }

    uint16_t new_id_be = htons(new_id);
    memcpy(buf_recv, &new_id_be, 2);

    sendto(remote_socket_fd, (const void*)buf_recv, msg_size, 0,
           (const struct sockaddr*)&remote_addr, sizeof(remote_addr));

    dns_message_free(&msg);
}
