#include "../include/DNS_server.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../include/DNS_struct.h"

int local_socket_fd = -1;
int remote_socket_fd = -1;
int sock_addr_len;

struct sockaddr_in local_addr;
struct sockaddr_in remote_addr;

char* dns_server_addr = "8.8.8.8";

void server_socket_init() {
    sock_addr_len = sizeof(local_addr);

    local_socket_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (local_socket_fd < 0) {
        // error
        perror("local socket failed");
    }
    remote_socket_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (remote_socket_fd < 0) {
        // error
        perror("remote socket failed");
    }

    memset(&local_addr, 0, sizeof(local_addr));
    memset(&remote_addr, 0, sizeof(remote_addr));

    local_addr.sin_family = AF_INET;
    local_addr.sin_addr.s_addr = INADDR_ANY;
    local_addr.sin_port = htons(53);

    remote_addr.sin_family = AF_INET;
    remote_addr.sin_addr.s_addr = inet_addr(dns_server_addr);
    remote_addr.sin_port = htons(53);

    int opt = 1;
    if (setsockopt(local_socket_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        // error
        perror("opt failed");
    }

    if (bind(local_socket_fd, (const struct sockaddr*)&local_addr, sizeof(local_addr)) < 0) {
        // error
        perror("bind failed");
    }
    printf("OK\n");
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
void server_mode_blocking_set() {}
void server_mode_non_blocking_set() {}
void remote_receive() {}
void local_receive() {
    uint8_t buf_recv[BUFFER_SIZE];
    uint8_t buf_to_send[BUFFER_SIZE];

    dns_message_t msg;
    uint8_t ip_addr[4] = {0, 0, 0, 0};

    int msg_size = -1;
    int cache_found = 0;

    msg_size = recvfrom(local_socket_fd, (void*)&buf_recv, sizeof(buf_recv), 0,
                        (struct sockaddr*)&local_addr, &sock_addr_len);

    // if()
}