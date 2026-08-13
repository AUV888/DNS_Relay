#ifndef DNS_CONVERT_H
#define DNS_CONVERT_H

#include "DNS_struct.h"
/*
@brief A function to read bytes that caller do not need to use ntoh every time.
@param buf Pointer of pointer of buffer
@param bytes Byte count (1~4)
@return Value in uint32_t
*/
uint32_t convert_read_bytes(uint8_t** buf, int bytes);

/*
@brief A utility function to get dns question
@param msg Output DNS message structure (MUST be allocated by caller)
@param buf Pointer of buffer
@param start The start of the whole dns message (SHOULD be given by dns_message_decode function)
@param end One-past-end pointer of the packet buffer (for bounds checking)
@return New buffer pointer, or NULL on error
*/
uint8_t* get_dns_question(uint8_t* buf, uint8_t* start, const uint8_t* end);

/*
@brief A utility function to get dns answer
@param msg Output DNS message structure (MUST be allocated by caller)
@param buf Pointer of buffer
@param start The start of the whole dns message (SHOULD be given by dns_message_decode function)
@param end One-past-end pointer of the packet buffer (for bounds checking)
@return New buffer pointer, or NULL on error
*/
uint8_t* get_dns_answer(uint8_t* buf, uint8_t* start, const uint8_t* end, char* name_out,
                        uint32_t* ipv4_out, char* is_A_type, uint32_t* ttl_out);


/* -----------------------------------------------------------------------
 * Fast path: parse only the query header + first question (no heap alloc).
 * Used for cache-hit responses to avoid malloc/free in the hot path.
 * ----------------------------------------------------------------------- */

typedef struct {
    uint16_t id;                       /* transaction ID (host byte order) */
    uint16_t flags;                    /* original flags from client query  */
    char q_name[DNS_RR_NAME_MAX_SIZE]; /* decoded domain name  */
    uint16_t q_type;                   /* QTYPE (host byte order)           */
    uint16_t q_class;                  /* QCLASS (host byte order)          */
    /* Pointer to the raw question wire bytes (for copying into reply). */
    const uint8_t* q_wire_start; /* points inside the original buf    */
    int q_wire_len;              /* length of the question section    */
} dns_query_fast_t;

/*
 * @brief Parse a DNS query packet into dns_query_fast_t without any heap
 *        allocation.  Only the first question record is decoded.
 *
 * @param buf   Raw packet bytes.
 * @param len   Packet length.
 * @param out   Caller-allocated output struct.
 * @return 1 on success, 0 on malformed/truncated input.
 */
int dns_query_decode_fast(const uint8_t* buf, int len, dns_query_fast_t* out);

/*
 * @brief Build a DNS A-record reply directly into dst without any heap
 *        allocation, using the pre-parsed query from dns_query_decode_fast.
 *
 * @param q        Query parsed by dns_query_decode_fast.
 * @param ip_addr  4-byte IPv4 address (big-endian array).
 * @param nxdomain If non-zero, set RCODE=NXDOMAIN and omit the answer RR.
 * @param dst      Output buffer (caller must ensure >= 512 bytes).
 * @return Number of bytes written, or -1 on error.
 */
int dns_reply_encode_fast(const dns_query_fast_t* q, const uint8_t ip_addr[4],
                          int nxdomain, uint8_t* dst);

#endif