#ifndef DNS_SERVER_H
#define DNS_SERVER_H

#include <arpa/inet.h>
#include <signal.h>
#include <sys/socket.h>

#define BUFFER_SIZE 1500
#define ID_LIST_SIZE 8192

extern long worker_thread_cnt;

extern int local_socket_fd;
extern int remote_socket_fd;
extern int sock_addr_len;
extern int dns_listen_port;
extern int dns_upstream_port;
extern volatile sig_atomic_t g_shutdown;
struct SET;   /* forward declaration, avoids pulling in DNS_cache.h */
extern struct SET* g_cache;

/*@brief Initialized the socket
 */
void server_socket_init();

/*@brief Close the socket
 */
void server_socket_close();
void server_mode_blocking_set();
void server_mode_non_blocking_set();
/* Returns 1 if a packet was processed, 0 if no more packets (EAGAIN/error). */
int remote_receive();
int local_receive();

#endif