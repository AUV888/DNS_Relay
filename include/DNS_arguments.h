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

/*
 * @brief Load a "IP domain" text file into the given cache.
 *        Each line has the format:  <dotted-decimal-ip> <domain>\n
 *        Lines starting with '#' and blank lines are ignored.
 *        An IP of 0.0.0.0 is stored as-is (used for NXDOMAIN blocking).
 *        Does nothing if cached_DNS_file == 0 or cached_file is empty.
 *
 * @param cache  Pointer to an already-initialised cache_set.
 *               Intentionally typed as void* to keep DNS_arguments.h
 *               free of DNS_cache.h / DNS_server.h dependencies.
 */
void load_cached_dns_file(void* cache);

#endif
