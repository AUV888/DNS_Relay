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

static void print_usage(const char* prog) {
    fprintf(stderr,
            "Usage: %s -s <server_ip> [options]\n"
            "\n"
            "Required:\n"
            "  -s, --server  <ipv4>      upstream DNS server address (dotted decimal)\n"
            "\n"
            "Optional:\n"
            "  -d, --debug   [log_file]  output debug log（file name is optional）\n"
            "  -m, --moredebug [log_file] output more detailed debug log（file name is optional）\n"
            "  -c, --cached  <file>      read cached DNS from file（file name is required）\n"
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
        if (c == 'd' || c == 'm' || c == 'c' || c == 's' || c == 'i')
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
    return '\0';
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

                if (!is_last && (opt == 'c' || opt == 's' || opt == 'i')) {
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
    }
}
