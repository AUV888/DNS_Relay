#ifndef DNS_ARGUMENTS_H
#define DNS_ARGUMENTS_H

extern char debug_mode;

extern char log_file[256];

extern char cached_DNS_file;

extern char cached_file[256];

extern char* dns_server_addr;

extern int dns_listen_port;
extern int dns_upstream_port;
extern char blocking_mode;

void parse_arguments(int argc, char* argv[]);

#endif
