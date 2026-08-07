/*
 * DNS_logparser.c — offline binary log parser for DNS_Relay.
 *
 * Usage:
 *   cat dns_relay.log | ./bin/Parser
 *   cat dns_relay.log | ./bin/Parser | grep "cache"
 *   cat dns_relay.log | ./bin/Parser --color | less -R
 *
 * The DNS_Relay server writes a binary log when run with -d / -dd (debug mode).
 * Each log_write(payload) call emits a fixed 16-byte record:
 *
 *   [timestamp : 8 bytes]   uint64_t, microseconds since epoch (gettimeofday)
 *   [payload  : 8 bytes]    uint64_t, bits 48..63 = event id (log_event_t),
 *                                   bits 32..47 = writer thread id
 *                                                 (0-based worker index, or
 *                                                 0xFFFF for the main thread),
 *                                   bits  0..31 = info field
 *
 * A few events are immediately followed by extra raw bytes written via
 * log_write_bytes().  Currently the only such event is CACHE_FIND_SRC, which
 * is followed by `src_len` bytes of the domain name (where src_len lives in
 * the info field of that same record).
 *
 * This program reads the binary stream from stdin in a loop until EOF and
 * prints one human-readable line per record.  Each line looks like:
 *
 *   [2026-08-06 11:46:10.123456] [pth3] [✅] Get DNS header id=4660 success.
 *   [2026-08-06 11:46:10.125956] [main] [ERROR] ID map erase error, You tried to erase slot 42 but it does not exist.
 *
 * The lowercase event name is kept as a tag right after the status prefix so
 * that pipeline filters such as `grep "cache"` or `grep "id_map"` still work.
 *
 * Colors (ANSI) are auto-enabled when stdout is a TTY.  Use --color to force
 * them on (e.g. when piping into `less -R`), or --no-color to force them off.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "../include/DNS_debug.h"
#include "../include/DNS_struct.h"

/* ----------------------------------------------------------------------- */
/* ANSI color helpers                                                       */
/* ----------------------------------------------------------------------- */

#define ANSI_RED     "\033[31m"
#define ANSI_GREEN   "\033[32m"
#define ANSI_YELLOW  "\033[33m"
#define ANSI_CYAN    "\033[36m"
#define ANSI_RESET   "\033[0m"

typedef enum { LOG_SUCCESS, LOG_ERROR, LOG_WARN, LOG_INFO } log_level_t;

static const char* level_label(log_level_t lv) {
    switch (lv) {
        case LOG_SUCCESS: return "\xE2\x9C\x85";  /* ✅ UTF-8 */
        case LOG_ERROR:   return "ERROR";
        case LOG_WARN:    return "WARN";
        case LOG_INFO:    return "INFO";
    }
    return "?";
}

static const char* level_color(log_level_t lv) {
    switch (lv) {
        case LOG_SUCCESS: return ANSI_GREEN;
        case LOG_ERROR:   return ANSI_RED;
        case LOG_WARN:    return ANSI_YELLOW;
        case LOG_INFO:    return ANSI_CYAN;
    }
    return "";
}

/* Classify an event into a severity level. */
static log_level_t event_level(log_event_t l) {
    switch (l) {
        /* ---- Errors (red [ERROR]) ---- */
        case LOCAL_SOCKET_FAILED:
        case REMOTE_SOCKET_FAILED:
        case SOCKET_OPT_FAILED:
        case SOCKET_BIND_FAILED:
        case LOCAL_RECEIVE_RECVFROM_FAILED:
        case LOCAL_RECEIVE_DECODE_NULL_HEADER:
        case LOCAL_RECEIVE_ANS_MALLOC_FAILED:
        case LOCAL_RECEIVE_ANS_NAME_MALLOC_FAILED:
        case LOCAL_RECEIVE_REPLY_SIZE_ERROR:
        case LOCAL_RECEIVE_NO_EMPTY_SLOT_DROP:
        case REMOTE_RECEIVE_MSG_SIZE_ERR:
        case REMOTE_RECEIVE_NO_ORIG_ID_DROP:
        case BLOCK_MODE_ERRNO_SELECT:
        case NON_BLOCK_MODE_LOCAL_FGETFL_ERR:
        case NON_BLOCK_MODE_LOCAL_FSETFL_ERR:
        case NON_BLOCK_MODE_REMOTE_FGETFL_ERR:
        case NON_BLOCK_MODE_REMOTE_FSETFL_ERR:
        case CREATE_HSET_ERR:
        case CONVERT_READ_BYTE_ERR:
        case GET_DNS_QUESTION_MALLOC_ERR:
        case GET_DNS_ANSWER_NULL_PTR_ERR:
        case GET_DNS_ANSWER_NOT_SUPPORTED_TYPE_ERR:
        case ID_MAP_INSERT_ARGS_NULL_PTR_ERR:
        case ID_MAP_INSERT_FULL_TABLE_ERR:
        case ID_MAP_FIND_ID_OUT_BOUND_ERR:
        case ID_MAP_FIND_USED_ID_ERR:
        case ID_MAP_FIND_TIMEOUT_ERR:
        case ID_MAP_ERASE_ID_OUT_BOUND_ERR:
        case ID_MAP_ERASE_ID_MAP_USED_ERR:
            return LOG_ERROR;

        /* ---- Warnings (yellow [WARN]) ---- */
        case BLOCK_MODE_ERRNO_EINTR:
        case BLOCK_MODE_TIMEOUT:
        case LOCAL_RECEIVE_CANNOT_HIT_CACHE:
        case REMOTE_RECEIVE_NO_GLOBAL_CACHE:
            return LOG_WARN;

        /* ---- Success (green [✅]) ---- */
        case SOCKET_INIT_SUCCESS:
        case SOCKET_CLOSE_SUCCESS:
        case LOCAL_RECEIVE_HIT_CACHE:
        case LOCAL_RECEIVE_DNS_MESSAGE_FREE_SUCCESS:
        case REMOTE_RECEIVE_SENT_TO_CLIENT:
        case REMOTE_RECEIVE_CACHED_ANSWER_SUCCESS:
        case CREATE_HSET_SUCCESS:
        case GET_DNS_HEADER_SUCCESS:
        case GET_DNS_QUESTION_SUCCESS:
        case GET_DNS_DOMAIN_SUCCESS:
        case GET_DNS_ANSWER_SUCCESS:
        case DNS_MESSAGE_DECODE_SUCCESS:
        case SET_DNS_HEADER_SUCCESS:
        case SET_DNS_DOMAIN_SUCCESS:
        case SET_DNS_QUESTION_SUCCESS:
        case SET_DNS_ANSWER_SUCCESS:
        case DNS_MESSAGE_ENCODE_SUCCESS:
        case DNS_MESSAGE_FREE_SUCCESS:
        case ID_MAP_FIND_SUCCESS:
        case ID_MAP_ERASED_SUCCESS:
        case ID_MAP_SWEEP_TIMEOUT_SUCCESS:
        case CACHE_FIND:
            return LOG_SUCCESS;

        /* ---- Info (cyan [INFO]) ---- */
        default:
            return LOG_INFO;
    }
}

/* ----------------------------------------------------------------------- */
/* Event name (lowercase, grep-friendly)                                    */
/* ----------------------------------------------------------------------- */

static const char* event_name(log_event_t l) {
    switch (l) {
        case LOCAL_SOCKET_FAILED:                    return "local_socket_failed";
        case REMOTE_SOCKET_FAILED:                   return "remote_socket_failed";
        case SOCKET_OPT_FAILED:                      return "socket_opt_failed";
        case SOCKET_BIND_FAILED:                     return "socket_bind_failed";
        case SOCKET_INIT_SUCCESS:                    return "socket_init_success";
        case SOCKET_CLOSE_SUCCESS:                   return "socket_close_success";
        case LOCAL_RECEIVE_RECVFROM_FAILED:          return "local_receive_recvfrom_failed";
        case LOCAL_RECEIVE_DECODE_NULL_HEADER:       return "local_receive_decode_null_header";
        case LOCAL_RECEIVE_CAN_RESOLVE_LOCALLY:      return "local_receive_can_resolve_locally";
        case LOCAL_RECEIVE_HIT_CACHE:                return "local_receive_hit_cache";
        case LOCAL_RECEIVE_ANS_MALLOC_FAILED:        return "local_receive_ans_malloc_failed";
        case LOCAL_RECEIVE_ANS_NAME_MALLOC_FAILED:  return "local_receive_ans_name_malloc_failed";
        case LOCAL_RECEIVE_REPLY_SIZE_ERROR:         return "local_receive_reply_size_error";
        case LOCAL_RECEIVE_DNS_MESSAGE_FREE_SUCCESS: return "local_receive_dns_message_free_success";
        case LOCAL_RECEIVE_CANNOT_HIT_CACHE:         return "local_receive_cannot_hit_cache";
        case LOCAL_RECEIVE_NO_EMPTY_SLOT_DROP:       return "local_receive_no_empty_slot_drop";
        case LOCAL_RECEIVE_SENT_TO_UPSTREAM:         return "local_receive_sent_to_upstream";
        case REMOTE_RECEIVE_MSG_SIZE_ERR:            return "remote_receive_msg_size_err";
        case REMOTE_RECEIVE_NO_ORIG_ID_DROP:         return "remote_receive_no_orig_id_drop";
        case REMOTE_RECEIVE_SENT_TO_CLIENT:          return "remote_receive_sent_to_client";
        case REMOTE_RECEIVE_NO_GLOBAL_CACHE:         return "remote_receive_no_global_cache";
        case REMOTE_RECEIVE_HAS_GLOBAL_CACHE:        return "remote_receive_has_global_cache";
        case REMOTE_RECEIVE_CACHED_ANSWER_SUCCESS:   return "remote_receive_cached_answer_success";
        case BLOCK_MODE_START:                       return "block_mode_start";
        case BLOCK_MODE_ERRNO_EINTR:                 return "block_mode_errno_eintr";
        case BLOCK_MODE_ERRNO_SELECT:                return "block_mode_errno_select";
        case BLOCK_MODE_TIMEOUT:                     return "block_mode_timeout";
        case BLOCK_MODE_LOCAL_RECEIVE:               return "block_mode_local_receive";
        case BLOCK_MODE_LOCAL_RECEIVE_NUM:           return "block_mode_local_receive_num";
        case BLOCK_MODE_REMOTE_RECEIVE:              return "block_mode_remote_receive";
        case BLOCK_MODE_REMOTE_RECEIVE_NUM:          return "block_mode_remote_receive_num";
        case NON_BLOCK_MODE_START:                   return "non_block_mode_start";
        case NON_BLOCK_MODE_LOCAL_FGETFL_ERR:        return "non_block_mode_local_fgetfl_err";
        case NON_BLOCK_MODE_LOCAL_FSETFL_ERR:        return "non_block_mode_local_fsetfl_err";
        case NON_BLOCK_MODE_REMOTE_FGETFL_ERR:       return "non_block_mode_remote_fgetfl_err";
        case NON_BLOCK_MODE_REMOTE_FSETFL_ERR:       return "non_block_mode_remote_fsetfl_err";
        case NON_BLOCK_MODE_LOCAL_RECEIVE:           return "non_block_mode_local_receive";
        case NON_BLOCK_MODE_REMOTE_RECEIVE:          return "non_block_mode_remote_receive";
        case NON_BLOCK_SWEEP:                        return "non_block_sweep";
        case CACHE_FIND:                             return "cache_find";
        case CACHE_CLEAR:                            return "cache_clear";
        case CACHE_ERASE:                            return "cache_erase";
        case CACHE_INSERT:                           return "cache_insert";
        case CACHE_DESTROY:                          return "cache_destroy";
        case CACHE_INIT:                             return "cache_init";
        case CREATE_HSET_ERR:                        return "create_hset_err";
        case CREATE_HSET_SUCCESS:                    return "create_hset_success";
        case CONVERT_READ_BYTE_ERR:                  return "convert_read_byte_err";
        case CONVERT_WRITE_BYTE:                     return "convert_write_byte";
        case GET_DNS_HEADER_SUCCESS:                 return "get_dns_header_success";
        case GET_DNS_QUESTION_MALLOC_ERR:            return "get_dns_question_malloc_err";
        case GET_DNS_QUESTION_SUCCESS:               return "get_dns_question_success";
        case GET_DNS_DOMAIN_SUCCESS:                 return "get_dns_domain_success";
        case GET_DNS_ANSWER_NULL_PTR_ERR:            return "get_dns_answer_null_ptr_err";
        case GET_DNS_ANSWER_NOT_SUPPORTED_TYPE_ERR:  return "get_dns_answer_not_supported_type_err";
        case GET_DNS_ANSWER_SUCCESS:                 return "get_dns_answer_success";
        case DNS_MESSAGE_DECODE_SUCCESS:             return "dns_message_decode_success";
        case SET_DNS_HEADER_SUCCESS:                 return "set_dns_header_success";
        case SET_DNS_DOMAIN_SUCCESS:                 return "set_dns_domain_success";
        case SET_DNS_QUESTION_SUCCESS:               return "set_dns_question_success";
        case SET_DNS_ANSWER_SUCCESS:                 return "set_dns_answer_success";
        case DNS_MESSAGE_ENCODE_SUCCESS:             return "dns_message_encode_success";
        case DNS_MESSAGE_FREE_SUCCESS:               return "dns_message_free_success";
        case ID_MAP_INIT:                            return "id_map_init";
        case ID_MAP_INSERT_ARGS_NULL_PTR_ERR:        return "id_map_insert_args_null_ptr_err";
        case ID_MAP_INSERT_FULL_TABLE_ERR:           return "id_map_insert_full_table_err";
        case ID_MAP_FIND_ID_OUT_BOUND_ERR:           return "id_map_find_id_out_bound_err";
        case ID_MAP_FIND_USED_ID_ERR:               return "id_map_find_used_id_err";
        case ID_MAP_FIND_TIMEOUT_ERR:                return "id_map_find_timeout_err";
        case ID_MAP_FIND_SUCCESS:                    return "id_map_find_success";
        case ID_MAP_ERASE_ID_OUT_BOUND_ERR:          return "id_map_erase_id_out_bound_err";
        case ID_MAP_ERASE_ID_MAP_USED_ERR:           return "id_map_erase_id_map_used_err";
        case ID_MAP_ERASED_SUCCESS:                  return "id_map_erased_success";
        case ID_MAP_SWEEP_TIMEOUT_SUCCESS:           return "id_map_sweep_timeout_success";
        case UI8_PTR_STACK_INIT:                     return "ui8_ptr_stack_init";
        case UI8_PTR_STACK_PUSH:                     return "ui8_ptr_stack_push";
        case UI8_PTR_STACK_POP:                      return "ui8_ptr_stack_pop";
        case CACHE_FIND_SRC:                         return "cache_find_src";
        case CACHE_FIND_HASH:                        return "cache_find_hash";
        default:                                     return "unknown_event";
    }
}

/* DNS RR type value -> short mnemonic for the answer-type log. */
static const char* dns_type_name(uint32_t t) {
    switch (t) {
        case DNS_TYPE_A:     return "A";
        case DNS_TYPE_NS:    return "NS";
        case DNS_TYPE_CNAME: return "CNAME";
        case DNS_TYPE_SOA:   return "SOA";
        case DNS_TYPE_PTR:   return "PTR";
        case DNS_TYPE_HINFO: return "HINFO";
        case DNS_TYPE_MINFO: return "MINFO";
        case DNS_TYPE_MX:    return "MX";
        case DNS_TYPE_TXT:   return "TXT";
        case DNS_TYPE_AAAA:  return "AAAA";
        default:             return "UNKNOWN";
    }
}

/* ----------------------------------------------------------------------- */
/* Formatting helpers                                                       */
/* ----------------------------------------------------------------------- */

/* Format the microsecond timestamp as "YYYY-MM-DD HH:MM:SS.uuuuuu". */
static void format_ts(uint64_t ts_us, char* buf, size_t bufsz) {
    time_t sec = (time_t)(ts_us / 1000000ULL);
    uint64_t us = ts_us % 1000000ULL;
    struct tm tm_info;
    localtime_r(&sec, &tm_info);
    strftime(buf, bufsz, "%Y-%m-%d %H:%M:%S", &tm_info);
    size_t len = strlen(buf);
    snprintf(buf + len, bufsz - len, ".%06llu", (unsigned long long)us);
}

/* Print an IPv4 address stored in the low 32 bits of the info field.
 * The cache stores IPv4 in host byte order (see DNS_cache.c), so we
 * decompose it as (a.b.c.d) directly. */
static void print_ipv4(uint64_t info) {
    uint32_t ip = (uint32_t)(info & 0xFFFFFFFFULL);
    printf("%u.%u.%u.%u", (ip >> 24) & 0xFFU, (ip >> 16) & 0xFFU,
           (ip >> 8) & 0xFFU, ip & 0xFFU);
}

/* Read exactly `n` bytes from stdin into `dst`.
 * Returns the number of bytes actually read (0 <= ret <= n).
 * On a short read the stream is at EOF; the caller should treat the
 * remainder of the log as corrupt/truncated. */
static size_t read_n_bytes(void* dst, size_t n) {
    return fread(dst, 1, n, stdin);
}

/* Skip `n` bytes from stdin without keeping them.  Used when a domain
 * string is pathologically long (longer than our local buffer). */
static void skip_n_bytes(uint64_t n) {
    char tmp[4096];
    while (n > 0) {
        size_t chunk = n < sizeof(tmp) ? (size_t)n : sizeof(tmp);
        size_t got = fread(tmp, 1, chunk, stdin);
        if (got == 0)
            return;
        n -= got;
    }
}

/* ----------------------------------------------------------------------- */
/* Print the status prefix:  [✅] event_name:  (with optional color)       */
/* ----------------------------------------------------------------------- */
static void print_prefix(log_level_t lv, int use_color) {
    if (use_color) {
        printf("%s[%s]%s %s%s ",
               level_color(lv), level_label(lv), ANSI_RESET,
               level_color(lv), ANSI_RESET);
    } else {
        printf("[%s] ", level_label(lv));
    }
}

/* ----------------------------------------------------------------------- */
/* Print the human-friendly message for a single event.                     */
/* `info` is the low 48 bits of the payload.  For CACHE_FIND_SRC this       */
/* function also consumes `src_len` follow-up bytes from stdin.             */
/* ----------------------------------------------------------------------- */
static void print_human_message(log_event_t ev, uint64_t info) {
    switch (ev) {
        /* ================================================================
         * SOCKET LIFECYCLE
         * ================================================================ */
        case LOCAL_SOCKET_FAILED:
            printf("Failed to create local socket."); break;
        case REMOTE_SOCKET_FAILED:
            printf("Failed to create remote socket."); break;
        case SOCKET_OPT_FAILED:
            printf("Failed to set socket options."); break;
        case SOCKET_BIND_FAILED:
            printf("Failed to bind socket."); break;
        case SOCKET_INIT_SUCCESS:
            printf("Socket initialized successfully."); break;
        case SOCKET_CLOSE_SUCCESS:
            printf("Socket closed successfully."); break;

        /* ================================================================
         * LOCAL RECEIVE (client -> relay)
         * ================================================================ */
        case LOCAL_RECEIVE_RECVFROM_FAILED:
            printf("recvfrom() failed on local socket."); break;
        case LOCAL_RECEIVE_DECODE_NULL_HEADER:
            printf("Cannot decode DNS message: header is null."); break;
        case LOCAL_RECEIVE_CAN_RESOLVE_LOCALLY:
            printf("Query can be resolved locally."); break;
        case LOCAL_RECEIVE_HIT_CACHE:
            printf("Cache hit! Replying from local cache."); break;
        case LOCAL_RECEIVE_ANS_MALLOC_FAILED:
            printf("Out of memory: cannot allocate answer struct."); break;
        case LOCAL_RECEIVE_ANS_NAME_MALLOC_FAILED:
            printf("Out of memory: cannot allocate answer name."); break;
        case LOCAL_RECEIVE_REPLY_SIZE_ERROR:
            printf("Reply size check failed."); break;
        case LOCAL_RECEIVE_DNS_MESSAGE_FREE_SUCCESS:
            printf("DNS message freed."); break;
        case LOCAL_RECEIVE_CANNOT_HIT_CACHE:
            printf("Cache miss, forwarding to upstream."); break;
        case LOCAL_RECEIVE_NO_EMPTY_SLOT_DROP:
            printf("ID map full, dropping query."); break;
        case LOCAL_RECEIVE_SENT_TO_UPSTREAM:
            printf("Query forwarded to upstream."); break;

        /* ================================================================
         * REMOTE RECEIVE (upstream -> relay)
         * ================================================================ */
        case REMOTE_RECEIVE_MSG_SIZE_ERR:
            printf("Remote message size error."); break;
        case REMOTE_RECEIVE_NO_ORIG_ID_DROP:
            printf("Cannot find original ID, dropping reply."); break;
        case REMOTE_RECEIVE_SENT_TO_CLIENT:
            printf("Reply sent back to client."); break;
        case REMOTE_RECEIVE_NO_GLOBAL_CACHE:
            printf("No global cache available."); break;
        case REMOTE_RECEIVE_HAS_GLOBAL_CACHE:
            printf("Global cache available."); break;
        case REMOTE_RECEIVE_CACHED_ANSWER_SUCCESS:
            printf("Answer cached successfully."); break;

        /* ================================================================
         * BLOCK / NON-BLOCK EVENT LOOP
         * ================================================================ */
        case BLOCK_MODE_START:
            printf("Block mode event loop started."); break;
        case BLOCK_MODE_ERRNO_EINTR:
            printf("select() interrupted by signal (EINTR)."); break;
        case BLOCK_MODE_ERRNO_SELECT:
            printf("select() failed in block mode."); break;
        case BLOCK_MODE_TIMEOUT:
            printf("select() timed out (30s heartbeat, housekeeping still runs every 1s).");
            break;
        case BLOCK_MODE_LOCAL_RECEIVE:
            printf("Block mode: trying to receive from local socket."); break;
        case BLOCK_MODE_LOCAL_RECEIVE_NUM: {
            printf("Block mode: received %u from local socket.", (unsigned)info);
            break;            
        }
        case BLOCK_MODE_REMOTE_RECEIVE:
            printf("Block mode: trying to receive from remote socket."); break;
        case BLOCK_MODE_REMOTE_RECEIVE_NUM: {
            printf("Block mode: received %u from remote socket.", (unsigned)info);
            break;            
        }
        case NON_BLOCK_MODE_START:
            printf("Non-block mode event loop started."); break;
        case NON_BLOCK_MODE_LOCAL_FGETFL_ERR:
            printf("fcntl(F_GETFL) failed on local socket."); break;
        case NON_BLOCK_MODE_LOCAL_FSETFL_ERR:
            printf("fcntl(F_SETFL) failed on local socket."); break;
        case NON_BLOCK_MODE_REMOTE_FGETFL_ERR:
            printf("fcntl(F_GETFL) failed on remote socket."); break;
        case NON_BLOCK_MODE_REMOTE_FSETFL_ERR:
            printf("fcntl(F_SETFL) failed on remote socket."); break;
        case NON_BLOCK_MODE_LOCAL_RECEIVE:
            printf("Non-block mode: receiving from local socket."); break;
        case NON_BLOCK_MODE_REMOTE_RECEIVE:
            printf("Non-block mode: receiving from remote socket."); break;
        case NON_BLOCK_SWEEP:
            printf("Non-block sweep triggered."); break;

        /* ================================================================
         * CACHE
         * ================================================================ */
        case CACHE_FIND: {
            printf("Cache HIT! IPv4 = ");
            print_ipv4(info);
            printf(".");
            break;
        }
        case CACHE_FIND_SRC: {
            /* info = src_len; followed by `src_len` raw domain bytes. */
            uint32_t src_len = (uint32_t)info;
            char domain[DNS_RR_NAME_MAX_SIZE];
            if (src_len < sizeof(domain)) {
                size_t got = read_n_bytes(domain, src_len);
                domain[got] = '\0';
                if (got < src_len) {
                    printf("Looking up domain \"%s\" (len=%u, TRUNCATED got=%zu) in cache...",
                           domain, (unsigned)src_len, got);
                } else {
                    printf("Looking up domain \"%s\" (len=%u) in cache...",
                           domain, (unsigned)src_len);
                }
            } else {
                /* Pathologically long domain: print what fits, skip the rest. */
                size_t got = read_n_bytes(domain, sizeof(domain) - 1);
                domain[got] = '\0';
                skip_n_bytes(src_len - (uint32_t)got);
                printf("Looking up domain \"%s\" (len=%u, TRUNCATED+skipped) in cache...",
                       domain, (unsigned)src_len);
            }
            break;
        }
        case CACHE_FIND_HASH: {
            uint32_t h = (uint32_t)(info & 0xFFFFFFFFULL);
            printf("Domain hash = 0x%08x.", h);
            break;
        }
        case CACHE_CLEAR:
            printf("Cache cleared."); break;
        case CACHE_ERASE:
            printf("Cache entry erased."); break;
        case CACHE_INSERT:
            printf("Cache entry inserted."); break;
        case CACHE_DESTROY:
            printf("Cache destroyed."); break;
        case CACHE_INIT:
            printf("Cache initialized."); break;
        case CREATE_HSET_ERR:
            printf("Out of memory: cannot create hash set."); break;
        case CREATE_HSET_SUCCESS:
            printf("Hash set created."); break;

        /* ================================================================
         * CONVERT (read/write byte helpers)
         * ================================================================ */
        case CONVERT_READ_BYTE_ERR:
            printf("Invalid byte count in convert_read_bytes (expected 1, 2, or 4).");
            break;
        case CONVERT_WRITE_BYTE:
            /* info = byte count written in this convert_write_bytes() call. */
            printf("Wrote %u byte(s) to DNS buffer.", (unsigned)info);
            break;

        /* ================================================================
         * DNS MESSAGE DECODE / ENCODE
         * ================================================================ */
        case GET_DNS_HEADER_SUCCESS: {
            /* info = DNS header id (uint16_t, lower 16 bits). */
            printf("Get DNS header id %u success.", (unsigned)(info & 0xFFFFU));
            break;
        }
        case GET_DNS_QUESTION_MALLOC_ERR:
            printf("Out of memory: cannot allocate DNS question."); break;
        case GET_DNS_QUESTION_SUCCESS:
            printf("Get DNS question success."); break;
        case GET_DNS_DOMAIN_SUCCESS:
            printf("Get DNS domain success."); break;
        case GET_DNS_ANSWER_NULL_PTR_ERR:
            printf("Out of memory: cannot allocate DNS answer RR."); break;
        case GET_DNS_ANSWER_NOT_SUPPORTED_TYPE_ERR:
            printf("Unsupported DNS RR type, skipping."); break;
        case GET_DNS_ANSWER_SUCCESS: {
            /* info = RR type (dns_type_t enum, stored as uint32_t). */
            uint32_t t = (uint32_t)(info & 0xFFFFFFFFULL);
            printf("Get DNS answer success, type=%s (%u).", dns_type_name(t), t);
            break;
        }
        case DNS_MESSAGE_DECODE_SUCCESS:
            printf("DNS message decoded successfully."); break;
        case SET_DNS_HEADER_SUCCESS:
            printf("DNS header set successfully."); break;
        case SET_DNS_DOMAIN_SUCCESS:
            printf("DNS domain set successfully."); break;
        case SET_DNS_QUESTION_SUCCESS:
            printf("DNS question set successfully."); break;
        case SET_DNS_ANSWER_SUCCESS:
            printf("DNS answer set successfully."); break;
        case DNS_MESSAGE_ENCODE_SUCCESS:
            printf("DNS message encoded successfully."); break;
        case DNS_MESSAGE_FREE_SUCCESS:
            printf("DNS message freed successfully."); break;

        /* ================================================================
         * ID MAP
         * ================================================================ */
        case ID_MAP_INIT:
            printf("ID map initialized."); break;
        case ID_MAP_INSERT_ARGS_NULL_PTR_ERR:
            printf("ID map insert error: NULL pointer argument."); break;
        case ID_MAP_INSERT_FULL_TABLE_ERR:
            printf("ID map full, cannot insert new mapping."); break;
        case ID_MAP_FIND_ID_OUT_BOUND_ERR:
            printf("ID map find error: new_id out of bounds."); break;
        case ID_MAP_FIND_USED_ID_ERR:
            printf("ID map find error: slot not in use."); break;
        case ID_MAP_FIND_TIMEOUT_ERR:
            printf("ID map find error: slot timed out."); break;
        case ID_MAP_FIND_SUCCESS:
            printf("ID map find success."); break;
        case ID_MAP_ERASE_ID_OUT_BOUND_ERR:
            printf("ID map erase error: new_id out of bounds."); break;
        case ID_MAP_ERASE_ID_MAP_USED_ERR: {
            /* info = new_id that we tried to erase but was unused. */
            printf("ID map erase error, You tried to erase slot %u but it does not exist.",
                   (unsigned)(info & 0xFFFFU));
            break;
        }
        case ID_MAP_ERASED_SUCCESS: {
            /* info = new_id of the slot that was just released. */
            printf("ID map slot %u erased successfully.", (unsigned)(info & 0xFFFFU));
            break;
        }
        case ID_MAP_SWEEP_TIMEOUT_SUCCESS: {
            /* info = number of timed-out slots released in this sweep. */
            printf("ID map sweep done, released %u timed-out slot(s).", (unsigned)info);
            break;
        }

        /* ================================================================
         * UI8 PTR STACK
         * ================================================================ */
        case UI8_PTR_STACK_INIT:
            printf("Pointer stack initialized."); break;
        case UI8_PTR_STACK_PUSH:
            printf("Pointer pushed to stack."); break;
        case UI8_PTR_STACK_POP:
            printf("Pointer popped from stack."); break;

        default:
            /* Unknown event id — surface the raw info for debuggability. */
            if (info != 0) {
                printf("Unknown event, info=0x%08llx.", (unsigned long long)info);
            } else {
                printf("Unknown event.");
            }
            break;
    }
}

/* ----------------------------------------------------------------------- */
/* Main loop                                                                */
/* ----------------------------------------------------------------------- */

int main(int argc, char** argv) {
    /* Default: enable ANSI color iff stdout is a TTY. */
    int use_color = isatty(STDOUT_FILENO);
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--color") == 0) {
            use_color = 1;
        } else if (strcmp(argv[i], "--no-color") == 0) {
            use_color = 0;
        } else {
            fprintf(stderr,
                    "Parser: unknown argument '%s'\n"
                    "Usage: cat dns_relay.log | ./bin/Parser [--color|--no-color]\n",
                    argv[i]);
            return 1;
        }
    }

    /* Use a larger output buffer when stdout is piped — this keeps
     * `cat huge.log | ./bin/Parser | grep ...` fast. */
    static char outbuf[1 << 16];
    setvbuf(stdout, outbuf, _IOFBF, sizeof(outbuf));

    uint64_t ts, pl;
    char tbuf[64];

    /* Main loop: read 16-byte records until EOF. */
    while (fread(&ts, sizeof(ts), 1, stdin) == 1) {
        if (fread(&pl, sizeof(pl), 1, stdin) != 1) {
            fprintf(stderr, "logparser: truncated tail (missing payload)\n");
            break;
        }

        log_event_t ev = (log_event_t)((pl & EVENT_MASK) >> 48);
        uint16_t thread_id = (uint16_t)((pl & THREAD_MASK) >> 32);
        uint64_t info = pl & INFO_MASK;

        format_ts(ts, tbuf, sizeof(tbuf));

        /* Fixed header: [timestamp] [writer thread] */
        printf("[%s] ", tbuf);
        if (thread_id == LOG_THREAD_ID_MAIN) {
            printf("[main] ");
        } else {
            printf("[pth%u] ", (unsigned)thread_id);
        }

        /* Status prefix: [✅]/[ERROR]/[WARN]/[INFO] + lowercase event_name + ":" */
        print_prefix(event_level(ev), use_color);

        /* Human-friendly message (event-specific). */
        print_human_message(ev, info);

        printf("\n");
    }

    return 0;
}
