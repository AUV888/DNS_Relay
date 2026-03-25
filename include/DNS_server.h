#ifndef DNS_SERVER_H
#define DNS_SERVER_H

#include <arpa/inet.h>
#include <sys/socket.h>

#define DNS_PORT 53
#define BUFFER_SIZE 1500
#define ID_LIST_SIZE 128

extern int local_socket_fd;
extern int remote_socket_fd;
extern int sock_addr_len;

/*@brief Initialized the socket
 */
void server_socket_init();

/*@brief Close the socket
 */
void server_socket_close();
void server_mode_blocking_set();
void server_mode_non_blocking_set();
void remote_receive();
void local_receive();

#endif