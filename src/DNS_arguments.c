#include "../include/DNS_arguments.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

char debug_mode = 0;
char log_file[256] = {0};

char cached_DNS_file = 0;
char cached_file[256] = {0};

char* dns_server_addr = NULL;

int dns_listen_port = 53;
int dns_upstream_port = 53;

char blocking_mode = 1;

static void print_usage(const char* prog) {
    fprintf(stderr,
            "Usage: %s -s <server_ip> [options]\n"
            "\033[31m\033[1mNEVER SET UPSTREAM DNS SERVER ADDRESS AS LOOPBACK (127.0.0.0/8)! STORM WILL HAPPEN!\n\033[0m"
            "\033[33mNote: This program can reach its limit at approximately 10,000 QPS.\n"
            "Please use \033[1mUSE IT PROPERLY \033[0m\033[33mif your organization has DNS traffic restrictions.\n\033[0m"
            "\n"
            "Required:\n"
            "  -s, --server       <ipv4>     upstream DNS server address (dotted decimal)\n"
            "\n"
            "Optional:\n"
            "  -d, --debug        [log_file] output debug log (file name is optional)\n"
            "  -m, --moredebug    [log_file] output more detailed debug log (file name is optional)\n"
            "  -c, --cached       <file>     read cached DNS from file (file name is required)\n"
            "  -n, --nonblocking             use non-blocking mode (no argument; default is blocking)\n"
            "  -l, --listenport   <1-65535>  local port to listen for DNS queries (default 53)\n"
            "  -u, --upstreamport <1-65535>  upstream DNS server port (default 53)\n"
            "\n"
            "  GNU argument style is supported\n"
            "  -d, --d and --debug have no difference\n",
            prog);
    exit(1);
}

static void make_default_log_name(char* buf, size_t size) {
    time_t now = time(NULL);
    struct tm* t = localtime(&now);
    snprintf(buf, size, "DNS_Relay_%04d%02d%02d_%02d%02d%02d.log", t->tm_year + 1900, t->tm_mon + 1,
             t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec);
}

static int is_option(const char* s) { return s && s[0] == '-'; }

static char long_to_short(const char* name) {
    if (name[1] == '\0') {
        char c = name[0];
        if (c == 'd' || c == 'm' || c == 'c' || c == 's' || c == 'i' ||
            c == 'n' || c == 'l' || c == 'u')
            return c;
        return '\0';
    }
    if (strcmp(name, "debug") == 0)
        return 'd';
    if (strcmp(name, "moredebug") == 0)
        return 'm';
    if (strcmp(name, "cached") == 0)
        return 'c';
    if (strcmp(name, "server") == 0)
        return 's';
    if (strcmp(name, "nonblocking") == 0)
        return 'n';
    if (strcmp(name, "listenport") == 0)
        return 'l';
    if (strcmp(name, "upstreamport") == 0)
        return 'u';
    return '\0';
}

/*
 * Parse a string as a TCP/UDP port number (1 ~ 65535).
 * Returns the parsed value, or -1 on any error (non-digit, out of range, empty).
 */
static int parse_port_arg(const char* s) {
    if (!s || *s == '\0')
        return -1;
    long v = 0;
    for (const char* p = s; *p; p++) {
        if (*p < '0' || *p > '9')
            return -1;
        v = v * 10 + (*p - '0');
        if (v > 65535)
            return -1;
    }
    if (v < 1 || v > 65535)
        return -1;
    return (int)v;
}

static int handle_short(char opt, int argc, char* argv[], int i, const char* prog) {
    switch (opt) {
        case 'd':
            if (debug_mode < 1)
                debug_mode = 1;
            if (i + 1 < argc && !is_option(argv[i + 1])) {
                strncpy(log_file, argv[i + 1], 255);
                log_file[255] = '\0';
                return 1;
            } else {
                if (log_file[0] == '\0')
                    make_default_log_name(log_file, sizeof(log_file));
            }
            return 0;

        case 'm':
            debug_mode = 2;
            if (i + 1 < argc && !is_option(argv[i + 1])) {
                strncpy(log_file, argv[i + 1], 255);
                log_file[255] = '\0';
                return 1;
            } else {
                if (log_file[0] == '\0')
                    make_default_log_name(log_file, sizeof(log_file));
            }
            return 0;

        case 'c':
            if (i + 1 < argc && !is_option(argv[i + 1])) {
                cached_DNS_file = 1;
                strncpy(cached_file, argv[i + 1], 255);
                cached_file[255] = '\0';
                return 1;
            } else {
                fprintf(stderr, "Error: -c/--cached requires a file argument.\n");
                print_usage(prog);
            }
            break;

        case 's':
            if (i + 1 < argc && !is_option(argv[i + 1])) {
                dns_server_addr = argv[i + 1];
                return 1;
            } else {
                fprintf(stderr, "Error: -s/--server requires an IPv4 address argument.\n");
                print_usage(prog);
            }
            break;

        case 'n':
            /* Toggle non-blocking mode; consumes no extra argument. */
            blocking_mode = 0;
            return 0;

        case 'l':
            if (i + 1 < argc && !is_option(argv[i + 1])) {
                int port = parse_port_arg(argv[i + 1]);
                if (port < 0) {
                    fprintf(stderr,
                            "Error: -l/--listenport requires a number in 1~65535, got '%s'.\n",
                            argv[i + 1]);
                    print_usage(prog);
                }
                dns_listen_port = port;
                return 1;
            } else {
                fprintf(stderr,
                        "Error: -l/--listenport requires a port number (1~65535).\n");
                print_usage(prog);
            }
            break;

        case 'u':
            if (i + 1 < argc && !is_option(argv[i + 1])) {
                int port = parse_port_arg(argv[i + 1]);
                if (port < 0) {
                    fprintf(stderr,
                            "Error: -u/--upstreamport requires a number in 1~65535, got '%s'.\n",
                            argv[i + 1]);
                    print_usage(prog);
                }
                dns_upstream_port = port;
                return 1;
            } else {
                fprintf(stderr,
                        "Error: -u/--upstreamport requires a port number (1~65535).\n");
                print_usage(prog);
            }
            break;

        default:
            fprintf(stderr, "Error: Unknown option '-%c'.\n", opt);
            print_usage(prog);
    }
    return 0;
}

void parse_arguments(int argc, char* argv[]) {
    const char* prog = argc > 0 ? argv[0] : "DNS_Relay";

    for (int i = 1; i < argc;) {
        const char* arg = argv[i];

        if (arg[0] != '-') {
            fprintf(stderr, "Error: Unexpected argument '%s'.\n", arg);
            print_usage(prog);
        }

        if (arg[1] == '-') {
            const char* name = arg + 2;
            if (*name == '\0') {
                i++;
                break;
            }
            char shortopt = long_to_short(name);
            if (shortopt == '\0') {
                fprintf(stderr, "Error: Unknown option '%s'.\n", arg);
                print_usage(prog);
            }
            i += 1 + handle_short(shortopt, argc, argv, i, prog);

        } else {
            const char* p = arg + 1;
            if (*p == '\0') {
                fprintf(stderr, "Error: Lone '-' is not a valid option.\n");
                print_usage(prog);
            }

            int extra = 0;
            while (*p) {
                char opt = *p;
                p++;
                int is_last = (*p == '\0');

                if (!is_last && (opt == 'c' || opt == 's' || opt == 'i' ||
                                 opt == 'l' || opt == 'u')) {
                    fprintf(stderr,
                            "Error: Option '-%c' requires an argument and "
                            "must be the last in a combined option string.\n",
                            opt);
                    print_usage(prog);
                }
                if (!is_last && (opt == 'd' || opt == 'm')) {
                    if (opt == 'd' && debug_mode < 1)
                        debug_mode = 1;
                    if (opt == 'm')
                        debug_mode = 2;
                    if (log_file[0] == '\0')
                        make_default_log_name(log_file, sizeof(log_file));
                } else if (!is_last && opt == 'n') {
                    /* -n takes no argument, can appear anywhere in combined form */
                    blocking_mode = 0;
                } else {
                    extra = handle_short(opt, argc, argv, i, prog);
                }
            }
            i += 1 + extra;
        }
    }

    if (dns_server_addr == NULL) {
        fprintf(stderr, "Error: -s/--server <ipv4> is required.\n");
        print_usage(prog);
    } else if (dns_server_addr[0] == '1' && dns_server_addr[1] == '2' && dns_server_addr[2] == '7') {
        fprintf(stderr, "\033[31m\033[1mFATAL: STORM WILL HAPPEN IF UPSTREAM IPV4 IS LOOPBACK!\n\033[0m");
        print_usage(prog);
    }
}

/* -----------------------------------------------------------------------
 * load_cached_dns_file
 *
 * Reads a text file of the form:
 *     <dotted-decimal-ip> <domain>\n
 *
 * and inserts every valid entry into the supplied cache.
 * The cache pointer is typed void* so this translation unit does not
 * need to include DNS_cache.h or DNS_server.h, keeping coupling low.
 * The caller (main.c) casts g_cache (cache_set*) to void* when calling.
 * ----------------------------------------------------------------------- */
void load_cached_dns_file(void* cache) {
    if (!cached_DNS_file || cached_file[0] == '\0' || cache == NULL)
        return;

    FILE* fp = fopen(cached_file, "r");
    if (!fp) {
        fprintf(stderr, "load_cached_dns_file: cannot open '%s'\n",
                cached_file);
        return;
    }

    /* Forward-declare only what we need from DNS_cache to stay decoupled.
     * cache_insert signature: int cache_insert(cache_set*, char*, uint32_t, int) */
    extern int cache_insert(void*, char*, unsigned int, int);

    char line[640];   /* 255 (domain) + 1 (space) + 15 (ip) + newline + margin */
    int loaded = 0, skipped = 0;

    while (fgets(line, sizeof(line), fp) != NULL) {
        /* Strip trailing newline / carriage-return */
        size_t len = strlen(line);
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
            line[--len] = '\0';

        /* Skip blank lines and comments */
        if (len == 0 || line[0] == '#')
            continue;

        /* Parse:  <ip_str> <space(s)> <domain> */
        char ip_str[40] = {0};
        char domain[512] = {0};
        if (sscanf(line, "%39s %511s", ip_str, domain) != 2) {
            skipped++;
            continue;
        }

        /* Convert dotted-decimal to uint32_t (host byte order) */
        unsigned int a, b, c, d;
        if (sscanf(ip_str, "%u.%u.%u.%u", &a, &b, &c, &d) != 4 ||
            a > 255 || b > 255 || c > 255 || d > 255) {
            skipped++;
            continue;
        }
        unsigned int ip = (a << 24) | (b << 16) | (c << 8) | d;

        /* TTL = 0 means "never expire" — use INT_MAX as a practical sentinel */
        if (cache_insert(cache, domain, ip, 0x7fffffff))
            loaded++;
        else
            skipped++;
    }

    fclose(fp);
    fprintf(stdout, "load_cached_dns_file: loaded %d, skipped %d from '%s'\n",
            loaded, skipped, cached_file);
}
