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

/* Forward declaration: fast_decode_name() is defined in the fast-path helper
 * section below, but the (heap-free) question/answer walkers above call it. */
static const uint8_t* fast_decode_name(const uint8_t* pos, const uint8_t* pkt_start,
                                       const uint8_t* pkt_end, char* result, int* result_len);

uint8_t* get_dns_question(dns_message_t* msg, uint8_t* buf, uint8_t* start, const uint8_t* end) {
    int qd_cnt = (start[4] << 8) | start[5], i = 0, idx = 0;
    char name[DNS_RR_NAME_MAX_SIZE] = {};
    for (i = 0; i < qd_cnt; i++) {
        /* fast_decode_name() is a read-only walker; the caller's buffer is
         * mutable here, so the const result is cast back. */
        buf = (uint8_t*)fast_decode_name(buf, start, end, name, &idx);
        if (buf == NULL) {
            return NULL;
        }

        /* Need 4 bytes for qtype + qclass */
        if (buf + 4 > end) {
            return NULL;
        }

        (void)convert_read_bytes(&buf, 2);  // QTYPE
        (void)convert_read_bytes(&buf, 2);  // QCLASS
    }
    if (debug_mode) {
        log_event_t l = GET_DNS_QUESTION_SUCCESS;
        uint64_t pl = EVENT_MASK & ((uint64_t)l << 48);
        log_write(pl);
    }
    return buf;
}

uint8_t* get_dns_answer(uint8_t* buf, uint8_t* start, const uint8_t* end, char* name_out,
                        uint32_t* ipv4_out, char* is_A_type, uint32_t* ttl_out) {
    int an_cnt = (start[6] << 8) | start[7];
    for (int i = 0; i < an_cnt; i++) {
        int idx = 0;
        buf = (uint8_t*)fast_decode_name(buf, start, end, name_out, &idx);
        if (buf == NULL) {
            *is_A_type = 0;
            return NULL;
        }
        /* Need 14 bytes: type(2) + class(2) + ttl(4) + rdlength(2) + ip(4) */
        if (buf + 14 > end) {
            *is_A_type = 0;
            return NULL;
        }

        dns_type_t type = (dns_type_t)convert_read_bytes(&buf, 2);
        if (type != DNS_TYPE_A) {
            *is_A_type = 0;
            return NULL;
        }
        *is_A_type = 1;
        (void)convert_read_bytes(&buf, 2);  // QCLASS
        *ttl_out = convert_read_bytes(&buf, 4);
        (void)convert_read_bytes(&buf, 2);  // RDLENGTH
        *ipv4_out = convert_read_bytes(&buf, 4);
        return buf;
    }
    return NULL; /* no answer records -> nothing to cache */
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
const uint8_t* fast_decode_name(const uint8_t* pos, const uint8_t* pkt_start,
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
