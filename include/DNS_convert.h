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
@brief A function to write bytes that caller do not need to use hton every time.
@param buf Pointer of pointer of buffer
@param bytes Byte count (1~4)
@param value The data that should be written to buffer, in uint32_t
@return None
*/
void convert_write_bytes(uint8_t** buf, int bytes, uint32_t value);

/*
@brief A function to convert binary data from buffer to dns_message_t
@param msg Output DNS message structure (MUST be allocated by caller)
@param buf Pointer of buffer
@param len Length of DNS message in bytes (used for bounds checking)
*/
void dns_message_decode(dns_message_t* msg, uint8_t* buf, int len);

/*
@brief A utility function to get dns header
@param msg Output DNS message structure (MUST be allocated by caller)
@param buf Pointer of buffer
@param end One-past-end pointer of the packet buffer (for bounds checking)
@return New buffer pointer, or NULL on truncated input
*/
static inline uint8_t* get_dns_header(dns_message_t* msg, uint8_t* buf,
                                       const uint8_t* end);

/*
@brief A utility function to get dns question
@param msg Output DNS message structure (MUST be allocated by caller)
@param buf Pointer of buffer
@param start The start of the whole dns message (SHOULD be given by dns_message_decode function)
@param end One-past-end pointer of the packet buffer (for bounds checking)
@return New buffer pointer, or NULL on error
*/
static inline uint8_t* get_dns_question(dns_message_t* msg, uint8_t* buf,
                                         uint8_t* start, const uint8_t* end);

/*
@brief A utility function to get dns domain where it is represented in compression
@param result Place to store domain (MUST be allocated by caller)
@param idx Utility variable
@param buf Pointer of pointer of buffer
@param start The start of the whole dns message (SHOULD be given by dns_message_decode function)
@param end One-past-end pointer of the packet buffer (for bounds checking)
@return New buffer pointer, or NULL on error
*/
static inline uint8_t* get_dns_domain(char* result, int* idx, uint8_t** buf,
                                       uint8_t* start, const uint8_t* end);

/*
@brief A utility function to get dns answer
@param msg Output DNS message structure (MUST be allocated by caller)
@param buf Pointer of buffer
@param start The start of the whole dns message (SHOULD be given by dns_message_decode function)
@param end One-past-end pointer of the packet buffer (for bounds checking)
@return New buffer pointer, or NULL on error
*/
static inline uint8_t* get_dns_answer(dns_message_t* msg, uint8_t* buf,
                                       uint8_t* start, const uint8_t* end);

/*
@brief A function to convert from dns_message_t buffer to binary data in buffer
@param msg DNS message structure given
@param buf Pointer of buffer (caller MUST allocate buffer)
@param ip_addr IP address
*/
uint8_t* dns_message_encode(dns_message_t* msg, uint8_t* buf, uint8_t* ip_addr);

/*
@brief A utility function to set DNS header
@param msg DNS message structure given
@param buf Pointer of buffer (caller MUST allocate buffer)
@param ip_addr IP address
*/
static inline uint8_t* set_dns_header(dns_message_t* msg, uint8_t* buf, uint8_t* ip_addr);

/*
@brief A utility function to convert domain to DNS wire format
@param buf Pointer of buffer (caller MUST allocate buffer)
@param name Name of domain
*/
static inline uint8_t* set_dns_domain(uint8_t* buf, char* name);

/*
@brief A utility function to set DNS question
@param msg DNS message structure given
@param buf Pointer of buffer (caller MUST allocate buffer)
*/
static inline uint8_t* set_dns_question(dns_message_t* msg, uint8_t* buf);

/*
@brief A utility function to set DNS answer
@param msg DNS message structure given
@param buf Pointer of buffer (caller MUST allocate buffer)
@param ip_addr IP address
*/
static inline uint8_t* set_dns_answer(dns_message_t* msg, uint8_t* buf, uint8_t* ip_addr);

/*
@brief A function to free DNS message
@param msg DNS message structure given
*/
void dns_message_free(dns_message_t* msg);

/* -----------------------------------------------------------------------
 * Fast path: parse only the query header + first question (no heap alloc).
 * Used for cache-hit responses to avoid malloc/free in the hot path.
 * ----------------------------------------------------------------------- */

typedef struct {
    uint16_t id;             /* transaction ID (host byte order) */
    uint16_t flags;          /* original flags from client query  */
    char     q_name[DNS_RR_NAME_MAX_SIZE]; /* decoded domain name  */
    uint16_t q_type;         /* QTYPE (host byte order)           */
    uint16_t q_class;        /* QCLASS (host byte order)          */
    /* Pointer to the raw question wire bytes (for copying into reply). */
    const uint8_t* q_wire_start; /* points inside the original buf    */
    int            q_wire_len;   /* length of the question section    */
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