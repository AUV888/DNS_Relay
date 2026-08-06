#include "../include/DNS_convert.h"

#include <arpa/inet.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "../include/DNS_debug.h"
#include "../include/DNS_struct.h"
#include "../include/DNS_util.h"

uint32_t convert_read_bytes(uint8_t** buf, int bytes) {
    if (bytes == 1) {
        uint8_t val;
        memcpy(&val, *buf, 1);
        *buf += 1;
        return val;
    } else if (bytes == 2) {
        // DNS uses big-endian, read directly without ntohs
        uint16_t val = ((uint16_t)(*buf)[0] << 8) | (*buf)[1];
        *buf += 2;
        return val;
    } else if (bytes == 4) {
        // DNS uses big-endian, read directly without ntohl
        uint32_t val = ((uint32_t)(*buf)[0] << 24) | ((uint32_t)(*buf)[1] << 16) |
                       ((uint32_t)(*buf)[2] << 8) | (*buf)[3];
        *buf += 4;
        return val;
    } else {
        if (debug_mode) {
            log_event_t l = CONVERT_READ_BYTE_ERR;
            uint64_t pl = EVENT_MASK & ((uint64_t)l << 48);
            log_write(pl);
        }
        return 0xFFFFFFFF;
    }
}

void convert_write_bytes(uint8_t** buf, int bytes, uint32_t value) {
    if (bytes == 1) {
        memcpy(*buf, &value, 1);
        *buf += 1;
    } else if (bytes == 2) {
        // DNS uses big-endian, write directly without htons
        (*buf)[0] = (uint8_t)(value >> 8);
        (*buf)[1] = (uint8_t)(value & 0xFF);
        *buf += 2;
    } else if (bytes == 4) {
        // DNS uses big-endian, write directly without htonl
        (*buf)[0] = (uint8_t)(value >> 24);
        (*buf)[1] = (uint8_t)((value >> 16) & 0xFF);
        (*buf)[2] = (uint8_t)((value >> 8) & 0xFF);
        (*buf)[3] = (uint8_t)(value & 0xFF);
        *buf += 4;
    }
    if (debug_mode) {
        /* The log would be
         * [Timestamp : 8B][CONVERT_WRITE_BYTE : 2B][NULL : 2B][Byte Count : 4B]
         */
        log_event_t l = CONVERT_WRITE_BYTE;
        uint64_t pl = (EVENT_MASK & ((uint64_t)l << 48)) | (INFO_MASK & (uint64_t)bytes);
        log_write(pl);
    }
}

static inline uint8_t* get_dns_header(dns_message_t* msg, uint8_t* buf, const uint8_t* end) {
    /* Need exactly 12 bytes for a DNS header */
    if (buf + 12 > end)
        return NULL;
    msg->header->id = convert_read_bytes(&buf, 2);
    msg->header->flags = convert_read_bytes(&buf, 2);
    msg->header->qdcount = convert_read_bytes(&buf, 2);
    msg->header->ancount = convert_read_bytes(&buf, 2);
    msg->header->nscount = convert_read_bytes(&buf, 2);
    msg->header->arcount = convert_read_bytes(&buf, 2);

    if (debug_mode) {
        /* The log would be
         * [Timestamp : 8B][GET_DNS_HEADER_SUCCESS : 2B][NULL : 4B][id : 2B]
         */
        log_event_t l = GET_DNS_HEADER_SUCCESS;
        uint64_t pl = (EVENT_MASK & ((uint64_t)l << 48)) | (INFO_MASK & (uint64_t)msg->header->id);
        log_write(pl);
    }
    return buf;
}

static inline uint8_t* get_dns_domain(char* result, int* idx, uint8_t** buf, uint8_t* start,
                                      const uint8_t* end);

static inline uint8_t* get_dns_question(dns_message_t* msg, uint8_t* buf, uint8_t* start,
                                        const uint8_t* end) {
    int qd_cnt = msg->header->qdcount, i = 0, idx = 0;
    for (i = 0; i < qd_cnt; i++) {
        char name[DNS_RR_NAME_MAX_SIZE] = {0};
        dns_question_t* question_ptr = (dns_question_t*)malloc(sizeof(dns_question_t));

        if (question_ptr == NULL) {
            if (debug_mode) {
                log_event_t l = GET_DNS_QUESTION_MALLOC_ERR;
                uint64_t pl = EVENT_MASK & ((uint64_t)l << 48);
                log_write(pl);
            }
            return buf;
        }

        uint8_t* new_buf = get_dns_domain(name, &idx, &buf, start, end);
        if (new_buf == NULL) {
            free(question_ptr);
            return NULL;
        }
        buf = new_buf;

        /* Need 4 bytes for qtype + qclass */
        if (buf + 4 > end) {
            free(question_ptr);
            return NULL;
        }

        question_ptr->q_name = (char*)malloc(strlen(name) + 1);
        if (question_ptr->q_name == NULL) {
            free(question_ptr);
            return NULL;
        }
        memcpy(question_ptr->q_name, name, strlen(name) + 1);

        question_ptr->q_type = convert_read_bytes(&buf, 2);
        question_ptr->q_class = convert_read_bytes(&buf, 2);

        question_ptr->next = msg->question;
        msg->question = question_ptr;
    }
    if (debug_mode) {
        log_event_t l = GET_DNS_QUESTION_SUCCESS;
        uint64_t pl = EVENT_MASK & ((uint64_t)l << 48);
        log_write(pl);
    }
    return buf;
}

static inline uint8_t* get_dns_domain(char* result, int* idx, uint8_t** buf, uint8_t* start,
                                      const uint8_t* end) {
    // states
    enum parser_state { READING_DATA = 0, READING_LENGTH = 1 };
    typedef enum parser_state parser_state_t;

    // initialize variables
    parser_state_t state = READING_LENGTH;
    int char_remain = 0, jmp_cnt = 0;

    // stack for compressed pointers
    ui8_ptr_stack_t stack;
    ui8_ptr_stack_init(&stack);

    while (1) {
        /* Bounds check before every dereference */
        if (*buf >= end)
            return NULL;

        // read char
        if (state == READING_DATA) {
            /* Bounds check: need 1 byte */
            if (*buf + 1 > end)
                return NULL;
            uint8_t ch = (uint8_t)convert_read_bytes(buf, 1);
            /* Bug #5 fix: NUL byte inside a label is not valid in DNS;
             * treat it as end-of-domain */
            if (ch == 0) {
                if (debug_mode) {
                    log_event_t l = GET_DNS_DOMAIN_SUCCESS;
                    uint64_t pl = EVENT_MASK & ((uint64_t)l << 48);
                    log_write(pl);
                }
                return *buf;
            }
            result[*idx] = (char)ch;
            (*idx)++;
            if ((*idx) > DNS_RR_NAME_MAX_SIZE)
                return *buf;
            char_remain--;
            if (char_remain == 0)
                state = READING_LENGTH;
        }
        // read length
        else {
            // is pointer
            if (**buf >= 0xC0) {
                /* Need 2 bytes for the pointer */
                if (*buf + 2 > end)
                    return NULL;
                uint8_t* pointer_start = *buf;
                uint16_t offset = (uint16_t)convert_read_bytes(buf, 2);
                offset &= 0x3FFF;
                /* Use ptrdiff_t comparison to avoid uint16_t truncation */
                if ((ptrdiff_t)offset >= (pointer_start - start)) {
                    // forward or self reference — reject
                    return NULL;
                }
                if (jmp_cnt >= MAX_DNS_JUMP) {
                    return NULL;
                }
                // push the position AFTER the pointer (where buf is now)
                ui8_ptr_stack_push(&stack, *buf);
                *buf = start + offset;
                jmp_cnt++;
                continue;  // continue from new position
            }
            // is a value or end of domain
            else {
                /* Bounds check already done at top of loop (*buf < end) */
                uint8_t length = (uint8_t)convert_read_bytes(buf, 1);
                if (length == 0) {         // end of domain
                    if (stack.top >= 0) {  // if stack is not empty, jump back
                        *buf = ui8_ptr_stack_pop(&stack);
                        return *buf;
                    } else {
                        return *buf;
                    }
                }
                if (*idx != 0) {
                    result[*idx] = '.';
                    (*idx)++;
                    if ((*idx) > DNS_RR_NAME_MAX_SIZE)
                        return *buf;
                }
                char_remain = length;
                state = READING_DATA;
            }
        }
    }
}

static inline uint8_t* get_dns_answer(dns_message_t* msg, uint8_t* buf, uint8_t* start,
                                      const uint8_t* end) {
    for (int i = 0; i < msg->header->ancount; i++) {
        char name[DNS_RR_NAME_MAX_SIZE] = {0};
        int idx = 0;
        dns_resource_record_t* rr_ptr =
            (dns_resource_record_t*)malloc(sizeof(dns_resource_record_t));
        if (rr_ptr == NULL) {
            if (debug_mode) {
                log_event_t l = GET_DNS_ANSWER_NULL_PTR_ERR;
                uint64_t pl = EVENT_MASK & ((uint64_t)l << 48);
                log_write(pl);
            }
            return buf;
        }
        memset(rr_ptr, 0, sizeof(*rr_ptr));

        uint8_t* new_buf = get_dns_domain(name, &idx, &buf, start, end);
        if (new_buf == NULL) {
            free(rr_ptr);
            return NULL;
        }
        buf = new_buf;

        /* Need 10 bytes: type(2) + class(2) + ttl(4) + rdlength(2) */
        if (buf + 10 > end) {
            free(rr_ptr);
            return NULL;
        }

        rr_ptr->name = (char*)malloc(strlen(name) + 1);
        if (rr_ptr->name == NULL) {
            free(rr_ptr);
            return NULL;
        }
        memcpy(rr_ptr->name, name, strlen(name) + 1);

        rr_ptr->type = convert_read_bytes(&buf, 2);
        rr_ptr->rr_class = convert_read_bytes(&buf, 2);
        rr_ptr->ttl = convert_read_bytes(&buf, 4);
        rr_ptr->rd_length = convert_read_bytes(&buf, 2);

        /* Bounds check: rdata must fit inside the packet */
        if (buf + rr_ptr->rd_length > end) {
            free(rr_ptr->name);
            free(rr_ptr);
            return NULL;
        }

        dns_type_t type = (dns_type_t)rr_ptr->type;
        switch (type) {
            case DNS_TYPE_A: {
                if (buf + 4 > end) {
                    free(rr_ptr->name);
                    free(rr_ptr);
                    return NULL;
                }
                for (int j = 0; j < 4; j++) {
                    rr_ptr->rd_data.a_record.ip_addr[j] = (uint8_t)convert_read_bytes(&buf, 1);
                }
                break;
            }
            case DNS_TYPE_AAAA: {
                if (buf + 16 > end) {
                    free(rr_ptr->name);
                    free(rr_ptr);
                    return NULL;
                }
                for (int j = 0; j < 16; j++) {
                    rr_ptr->rd_data.aaaa_record.ip_addr[j] = (uint8_t)convert_read_bytes(&buf, 1);
                }
                break;
            }
            case DNS_TYPE_SOA: {
                char mname[DNS_RR_NAME_MAX_SIZE] = {0}, rname[DNS_RR_NAME_MAX_SIZE] = {0};
                int m_idx = 0, r_idx = 0;
                uint8_t* nb1 = get_dns_domain(mname, &m_idx, &buf, start, end);
                if (nb1 == NULL) {
                    free(rr_ptr->name);
                    free(rr_ptr);
                    return NULL;
                }
                buf = nb1;
                uint8_t* nb2 = get_dns_domain(rname, &r_idx, &buf, start, end);
                if (nb2 == NULL) {
                    free(rr_ptr->name);
                    free(rr_ptr);
                    return NULL;
                }
                buf = nb2;

                if (buf + 20 > end) {
                    free(rr_ptr->name);
                    free(rr_ptr);
                    return NULL;
                }

                rr_ptr->rd_data.soa_record.mname = (char*)malloc(strlen(mname) + 1);
                if (rr_ptr->rd_data.soa_record.mname == NULL) {
                    free(rr_ptr->name);
                    free(rr_ptr);
                    return NULL;
                }
                memcpy(rr_ptr->rd_data.soa_record.mname, mname, strlen(mname) + 1);

                rr_ptr->rd_data.soa_record.rname = (char*)malloc(strlen(rname) + 1);
                if (rr_ptr->rd_data.soa_record.rname == NULL) {
                    free(rr_ptr->rd_data.soa_record.mname);
                    free(rr_ptr->name);
                    free(rr_ptr);
                    return NULL;
                }
                memcpy(rr_ptr->rd_data.soa_record.rname, rname, strlen(rname) + 1);

                rr_ptr->rd_data.soa_record.serial = convert_read_bytes(&buf, 4);
                rr_ptr->rd_data.soa_record.refresh = convert_read_bytes(&buf, 4);
                rr_ptr->rd_data.soa_record.retry = convert_read_bytes(&buf, 4);
                rr_ptr->rd_data.soa_record.expire = convert_read_bytes(&buf, 4);
                rr_ptr->rd_data.soa_record.minimum = convert_read_bytes(&buf, 4);
                break;
            }
            case DNS_TYPE_CNAME: {
                char cname[DNS_RR_NAME_MAX_SIZE] = {0};
                int c_idx = 0;
                uint8_t* nb = get_dns_domain(cname, &c_idx, &buf, start, end);
                if (nb == NULL) {
                    free(rr_ptr->name);
                    free(rr_ptr);
                    return NULL;
                }
                buf = nb;
                rr_ptr->rd_data.cname_record.cname = (char*)malloc(strlen(cname) + 1);
                if (rr_ptr->rd_data.cname_record.cname == NULL) {
                    free(rr_ptr->name);
                    free(rr_ptr);
                    return NULL;
                }
                memcpy(rr_ptr->rd_data.cname_record.cname, cname, strlen(cname) + 1);
                break;
            }
            case DNS_TYPE_MX: {
                if (buf + 2 > end) {
                    free(rr_ptr->name);
                    free(rr_ptr);
                    return NULL;
                }
                rr_ptr->rd_data.mx_record.preference = (uint16_t)convert_read_bytes(&buf, 2);
                char exchange[DNS_RR_NAME_MAX_SIZE] = {0};
                int e_idx = 0;
                uint8_t* nb = get_dns_domain(exchange, &e_idx, &buf, start, end);
                if (nb == NULL) {
                    free(rr_ptr->name);
                    free(rr_ptr);
                    return NULL;
                }
                buf = nb;
                rr_ptr->rd_data.mx_record.exchange = (char*)malloc(strlen(exchange) + 1);
                if (rr_ptr->rd_data.mx_record.exchange == NULL) {
                    free(rr_ptr->name);
                    free(rr_ptr);
                    return NULL;
                }
                memcpy(rr_ptr->rd_data.mx_record.exchange, exchange, strlen(exchange) + 1);
                break;
            }
            case DNS_TYPE_TXT: {
                rr_ptr->rd_data.txt_record.text = (char*)malloc(rr_ptr->rd_length + 1);
                if (rr_ptr->rd_data.txt_record.text == NULL) {
                    free(rr_ptr->name);
                    free(rr_ptr);
                    return NULL;
                }
                memcpy(rr_ptr->rd_data.txt_record.text, buf, rr_ptr->rd_length);
                rr_ptr->rd_data.txt_record.text[rr_ptr->rd_length] = '\0';
                buf += rr_ptr->rd_length;
                break;
            }
            default: {
                if (debug_mode) {
                    log_event_t l = GET_DNS_ANSWER_NOT_SUPPORTED_TYPE_ERR;
                    uint64_t pl = EVENT_MASK & ((uint64_t)l << 48);
                    log_write(pl);
                }
                buf += rr_ptr->rd_length;
                break;
            }
        }
        rr_ptr->next = msg->answer;
        msg->answer = rr_ptr;
        if (debug_mode) {
            /* The log would be
             * [Timestamp : 8B][GET_DNS_ANSWER_SUCCESS : 2B][NULL : 4B][Type : 2B]
             */
            log_event_t l = GET_DNS_ANSWER_SUCCESS;
            uint64_t pl = (EVENT_MASK & ((uint64_t)l << 48)) | (INFO_MASK & (uint64_t)type);
            log_write(pl);
        }
    }

    return buf;
}

void dns_message_decode(dns_message_t* msg, uint8_t* buf, int len) {
    if (len < 12) /* too short to hold a DNS header */
        return;

    uint8_t* start = buf;
    const uint8_t* end = buf + len;

    msg->header = (dns_header_t*)malloc(sizeof(dns_header_t));
    if (msg->header == NULL)
        return;

    buf = get_dns_header(msg, buf, end);
    if (buf == NULL)
        return;

    /* Sanity-clamp counts to avoid absurd loop iterations on garbage input */
    if (msg->header->qdcount > 16)
        msg->header->qdcount = 0;
    if (msg->header->ancount > 64)
        msg->header->ancount = 0;

    buf = get_dns_question(msg, buf, start, end);
    if (buf != NULL)
        buf = get_dns_answer(msg, buf, start, end);

    if (debug_mode) {
        log_event_t l = DNS_MESSAGE_DECODE_SUCCESS;
        uint64_t pl = EVENT_MASK & ((uint64_t)l << 48);
        log_write(pl);
    }
}

static inline uint8_t* set_dns_header(dns_message_t* msg, uint8_t* buf, uint8_t* ip_addr) {
    dns_header_t* header = msg->header;
    header->ancount = 1;
    uint16_t dns_flags = header->flags;
    DNS_SET_QR(dns_flags, 1);
    DNS_SET_AA(dns_flags, 1);
    DNS_SET_RA(dns_flags, 1);
    DNS_SET_RCODE(dns_flags,
                  (ip_addr[0] == 0 && ip_addr[1] == 0 && ip_addr[2] == 0 && ip_addr[3] == 0)
                      ? DNS_RCODE_NXDOMAIN
                      : DNS_RCODE_OK);
    convert_write_bytes(&buf, 2, header->id);
    convert_write_bytes(&buf, 2, dns_flags);
    convert_write_bytes(&buf, 2, header->qdcount);
    convert_write_bytes(&buf, 2, header->ancount);
    convert_write_bytes(&buf, 2, header->nscount);
    convert_write_bytes(&buf, 2, header->arcount);

    if (debug_mode) {
        log_event_t l = SET_DNS_HEADER_SUCCESS;
        uint64_t pl = EVENT_MASK & ((uint64_t)l << 48);
        log_write(pl);
    }
    return buf;
}

static inline uint8_t* set_dns_domain(uint8_t* buf, char* name) {
    char tmp[DNS_RR_NAME_MAX_SIZE] = {0};
    memcpy(&(tmp[1]), name, strlen(name));

    int dot_pos = 0, name_cnt = 0, i = 1;

    while (1) {
        if (tmp[i] == '.') {
            tmp[dot_pos] = name_cnt;
            name_cnt = 0;
            dot_pos = i;
        } else if (tmp[i] == '\0') {
            tmp[dot_pos] = name_cnt;
            tmp[i] = '\0';
            memcpy(buf, tmp, i + 1);
            buf += i + 1;
            return buf;
        } else {
            name_cnt++;
        }
        i++;
    }
    if (debug_mode) {
        log_event_t l = SET_DNS_DOMAIN_SUCCESS;
        uint64_t pl = EVENT_MASK & ((uint64_t)l << 48);
        log_write(pl);
    }
}

static inline uint8_t* set_dns_question(dns_message_t* msg, uint8_t* buf) {
    dns_question_t* q_ptr = msg->question;
    for (int i = 0; i < msg->header->qdcount; i++) {
        buf = set_dns_domain(buf, q_ptr->q_name);
        convert_write_bytes(&buf, 2, q_ptr->q_type);
        convert_write_bytes(&buf, 2, q_ptr->q_class);
        q_ptr = q_ptr->next;
    }
    if (debug_mode) {
        log_event_t l = SET_DNS_QUESTION_SUCCESS;
        uint64_t pl = EVENT_MASK & ((uint64_t)l << 48);
        log_write(pl);
    }
    return buf;
}

static inline uint8_t* set_dns_answer(dns_message_t* msg, uint8_t* buf, uint8_t* ip_addr) {
    dns_resource_record_t* ans_ptr = msg->answer;
    for (int i = 0; i < msg->header->ancount; i++) {
        buf = set_dns_domain(buf, ans_ptr->name);
        convert_write_bytes(&buf, 2, ans_ptr->type);
        convert_write_bytes(&buf, 2, ans_ptr->rr_class);
        convert_write_bytes(&buf, 4, ans_ptr->ttl);
        convert_write_bytes(&buf, 2, ans_ptr->rd_length);
        for (int j = 0; j < 4; j++) {
            *buf = ip_addr[j];
            buf++;
        }

        ans_ptr = ans_ptr->next;
    }
    if (debug_mode) {
        log_event_t l = SET_DNS_ANSWER_SUCCESS;
        uint64_t pl = EVENT_MASK & ((uint64_t)l << 48);
        log_write(pl);
    }
    return buf;
}

uint8_t* dns_message_encode(dns_message_t* msg, uint8_t* buf, uint8_t* ip_addr) {
    buf = set_dns_header(msg, buf, ip_addr);
    buf = set_dns_question(msg, buf);
    buf = set_dns_answer(msg, buf, ip_addr);
    if (debug_mode) {
        log_event_t l = DNS_MESSAGE_ENCODE_SUCCESS;
        uint64_t pl = EVENT_MASK & ((uint64_t)l << 48);
        log_write(pl);
    }
    return buf;
}

void dns_message_free(dns_message_t* msg) {
    if (!msg)
        return;

    if (msg->header) {
        free(msg->header);
        msg->header = NULL;
    }

    dns_question_t* q = msg->question;
    while (q) {
        dns_question_t* nx = q->next;
        if (q->q_name)
            free(q->q_name);
        free(q);
        q = nx;
    }
    msg->question = NULL;

    dns_resource_record_t* a = msg->answer;
    while (a) {
        dns_resource_record_t* nx = a->next;
        if (a->name) {
            dns_type_t type = (dns_type_t)a->type;
            switch (type) {
                case DNS_TYPE_SOA:
                    if (a->rd_data.soa_record.mname)
                        free(a->rd_data.soa_record.mname);
                    if (a->rd_data.soa_record.rname)
                        free(a->rd_data.soa_record.rname);
                    break;
                case DNS_TYPE_CNAME: {
                    if (a->rd_data.cname_record.cname)
                        free(a->rd_data.cname_record.cname);
                    break;
                }
                case DNS_TYPE_MX: {
                    if (a->rd_data.mx_record.exchange)
                        free(a->rd_data.mx_record.exchange);
                    break;
                }
                case DNS_TYPE_TXT: {
                    if (a->rd_data.txt_record.text)
                        free(a->rd_data.txt_record.text);
                    break;
                }
                default:
                    break;
            }
            free(a->name);
        }
        free(a);
        a = nx;
    }
    msg->answer = NULL;
    if (debug_mode) {
        log_event_t l = DNS_MESSAGE_FREE_SUCCESS;
        uint64_t pl = EVENT_MASK & ((uint64_t)l << 48);
        log_write(pl);
    }
}

/* -----------------------------------------------------------------------
 * Fast-path helpers: zero-allocation query decode + reply encode
 * ----------------------------------------------------------------------- */

/*
 * Decode a DNS label sequence (possibly with compression pointers) into a
 * C string at `result`.  Returns a pointer to the byte AFTER the label
 * sequence in the original stream (i.e. the start of QTYPE), or NULL on
 * error.  Does NOT log — this is called from the fast path.
 *
 * Unlike get_dns_domain() this version does not update *buf via a pointer-
 * to-pointer; instead it takes the current read position as `pos` and
 * returns the new position via the return value.
 */
static const uint8_t* fast_decode_name(const uint8_t* pos, const uint8_t* pkt_start,
                                       const uint8_t* pkt_end, char* result, int* result_len) {
    int idx = 0;
    int jmp_cnt = 0;
    /* When we follow a compression pointer we need to continue from the
     * original stream position after the 2-byte pointer.  saved_pos is
     * set to that continuation address; once we reach end-of-name we
     * return saved_pos (not pos, which has wandered into compressed data). */
    const uint8_t* saved_pos = NULL;

    while (1) {
        if (pos >= pkt_end)
            return NULL;

        uint8_t b = *pos;

        if ((b & 0xC0) == 0xC0) {
            /* Compression pointer */
            if (pos + 2 > pkt_end)
                return NULL;
            if (jmp_cnt++ >= 10)
                return NULL;
            uint16_t offset = (uint16_t)(((b & 0x3F) << 8) | pos[1]);
            if (pkt_start + offset >= pos)
                return NULL; /* forward / self reference */
            if (saved_pos == NULL)
                saved_pos = pos + 2; /* remember where to resume */
            pos = pkt_start + offset;
            continue;
        }

        if (b == 0) {
            /* End of name */
            result[idx] = '\0';
            *result_len = idx;
            return (saved_pos != NULL) ? saved_pos : pos + 1;
        }

        /* Regular label length byte */
        uint8_t label_len = b;
        pos++;
        if (pos + label_len > pkt_end)
            return NULL;
        if (idx > 0) {
            if (idx + 1 >= DNS_RR_NAME_MAX_SIZE)
                return NULL;
            result[idx++] = '.';
        }
        if (idx + label_len >= DNS_RR_NAME_MAX_SIZE)
            return NULL;
        memcpy(result + idx, pos, label_len);
        idx += label_len;
        pos += label_len;
    }
}

int dns_query_decode_fast(const uint8_t* buf, int len, dns_query_fast_t* out) {
    if (!buf || len < 12 || !out)
        return 0;

    const uint8_t* p = buf;
    const uint8_t* end = buf + len;

    /* Header (12 bytes) */
    out->id = (uint16_t)((p[0] << 8) | p[1]);
    out->flags = (uint16_t)((p[2] << 8) | p[3]);
    uint16_t qdcount = (uint16_t)((p[4] << 8) | p[5]);
    p += 12;

    if (qdcount < 1)
        return 0;

    /* Question section */
    out->q_wire_start = p;
    int name_len = 0;
    const uint8_t* after_name = fast_decode_name(p, buf, end, out->q_name, &name_len);
    if (after_name == NULL)
        return 0;

    /* Need 4 bytes for QTYPE + QCLASS */
    if (after_name + 4 > end)
        return 0;

    out->q_type = (uint16_t)((after_name[0] << 8) | after_name[1]);
    out->q_class = (uint16_t)((after_name[2] << 8) | after_name[3]);
    out->q_wire_len = (int)((after_name + 4) - p);
    return 1;
}

int dns_reply_encode_fast(const dns_query_fast_t* q, const uint8_t ip_addr[4], int nxdomain,
                          uint8_t* dst) {
    if (!q || !ip_addr || !dst)
        return -1;

    uint8_t* p = dst;

    /* ---- Header (12 bytes) ---- */
    /* ID */
    p[0] = (uint8_t)(q->id >> 8);
    p[1] = (uint8_t)(q->id & 0xFF);
    /* Flags: QR=1, AA=1, RD copied from query, RA=1, RCODE */
    uint16_t flags = q->flags;
    DNS_SET_QR(flags, 1);
    DNS_SET_AA(flags, 1);
    DNS_SET_RA(flags, 1);
    DNS_SET_RCODE(flags, nxdomain ? DNS_RCODE_NXDOMAIN : DNS_RCODE_OK);
    p[2] = (uint8_t)(flags >> 8);
    p[3] = (uint8_t)(flags & 0xFF);
    /* QDCOUNT = 1 */
    p[4] = 0;
    p[5] = 1;
    /* ANCOUNT = 0 (NXDOMAIN) or 1 */
    p[6] = 0;
    p[7] = (uint8_t)(nxdomain ? 0 : 1);
    /* NSCOUNT = 0, ARCOUNT = 0 */
    p[8] = 0;
    p[9] = 0;
    p[10] = 0;
    p[11] = 0;
    p += 12;

    /* ---- Question section: copy raw wire bytes ---- */
    if (q->q_wire_len <= 0 || q->q_wire_start == NULL)
        return -1;
    memcpy(p, q->q_wire_start, (size_t)q->q_wire_len);
    p += q->q_wire_len;

    if (nxdomain)
        return (int)(p - dst);

    /* ---- Answer section ---- */
    /* Name: compression pointer back to offset 12 (start of question) */
    p[0] = 0xC0;
    p[1] = 0x0C;
    p += 2;
    /* TYPE A */
    p[0] = 0;
    p[1] = 1;
    p += 2;
    /* CLASS IN */
    p[0] = 0;
    p[1] = 1;
    p += 2;
    /* TTL = 300 */
    p[0] = 0;
    p[1] = 0;
    p[2] = 0x01;
    p[3] = 0x2C;
    p += 4;
    /* RDLENGTH = 4 */
    p[0] = 0;
    p[1] = 4;
    p += 2;
    /* RDATA: IPv4 address */
    p[0] = ip_addr[0];
    p[1] = ip_addr[1];
    p[2] = ip_addr[2];
    p[3] = ip_addr[3];
    p += 4;

    return (int)(p - dst);
}
