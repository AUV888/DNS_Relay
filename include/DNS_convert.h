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
@param len Length of DNS message
@return 0 for success, -1 for failure
*/
int dns_message_decode(dns_message_t* msg, const uint8_t* buf, size_t len);

/*
@brief A utility function to get dns header
@param msg Output DNS message structure (MUST be allocated by caller)
@param buf Pointer of buffer
@return New buffer pointer
*/
static inline uint8_t* get_dns_header(dns_message_t* msg, const uint8_t* buf);

/*
@brief A utility function to get dns question
@param msg Output DNS message structure (MUST be allocated by caller)
@param buf Pointer of buffer
@param start The start of the whole dns message (SHOULD be given by dns_message_decode function)
@return New buffer pointer
*/
static inline uint8_t* get_dns_question(dns_message_t* msg, const uint8_t* buf,
                                        const uint8_t* start);

/*
@brief A utility function to get dns domain where it is represented in compression
@param msg Output DNS message structure (MUST be allocated by caller)
@param buf Pointer of buffer
@param start The start of the whole dns message (SHOULD be given by dns_message_decode function)
@return New buffer pointer
*/
static inline uint8_t* get_dns_domain(dns_message_t* msg, const uint8_t* buf, const uint8_t* start);
#endif