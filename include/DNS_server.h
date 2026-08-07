#ifndef DNS_SERVER_H
#define DNS_SERVER_H

#include <arpa/inet.h>
#include <stdatomic.h>
#include <sys/socket.h>

#define BUFFER_SIZE 1500
#define ID_LIST_SIZE 8192

/* Number of worker threads.  Defined in main.c, initialized from
 * sysconf(_SC_NPROCESSORS_ONLN) before any thread is created. */
extern long worker_thread_cnt;

/* Legacy global sockets, used ONLY by the single-threaded non-blocking
 * mode (-n).  The multi-threaded blocking path never touches them: each
 * worker creates its own socket pair inside worker_main(). */
extern int local_socket_fd;
extern int remote_socket_fd;
extern int sock_addr_len;
extern int dns_listen_port;
extern int dns_upstream_port;

/* Shutdown flag: written by the SIGINT handler, polled by the event
 * loop(s).  _Atomic int is lock-free on all supported platforms, so a
 * store from a signal handler is async-signal-safe, and every polling
 * reader gets proper multi-core visibility. */
extern _Atomic int g_shutdown;
struct SET;   /* forward declaration, avoids pulling in DNS_cache.h */
extern struct SET* g_cache;

/* Per-worker execution context.  One instance per worker thread; nothing
 * inside it is shared with other threads. */
typedef struct worker_ctx {
    int tid;                        /* 0-based worker index */
    int local_fd;                   /* private listening socket (SO_REUSEPORT) */
    int remote_fd;                  /* private upstream socket */
    struct sockaddr_in remote_addr; /* read-only copy of the upstream endpoint */
} worker_ctx_t;

/*@brief Prepare addresses, cache and ID map.  Creates the legacy global
 *       sockets only for the single-threaded non-blocking mode; in the
 *       multi-threaded blocking mode each worker owns its own sockets.
 */
void server_socket_init();

/*@brief Close the socket
 */
void server_socket_close();
void server_mode_blocking_set();
void server_mode_non_blocking_set();
/* Returns 1 if a packet was processed, 0 if no more packets (EAGAIN/error). */
int remote_receive(worker_ctx_t* ctx);
int local_receive(worker_ctx_t* ctx);

#endif