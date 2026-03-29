#ifndef DNS_CONVERT_H
#define DNS_CONVERT_H

#include "DNS_struct.h"
/*
@brief A function to read bytes that caller do not need to use ntoh every time.
@param buf Pointer of pointer of buffer
@param bytes Byte count (1~4)
@return Value in uint32_t
*/
uint32_t convert_read_bytes(const uint8_t** buf, int bytes);

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
*/
void dns_message_decode(dns_message_t* msg, const uint8_t* buf);

/*
@brief A utility function to get dns header
@param msg Output DNS message structure (MUST be allocated by caller)
@param buf Pointer of buffer
@return New buffer pointer
*/
static inline const uint8_t* get_dns_header(dns_message_t* msg, const uint8_t* buf);

/*
@brief A utility function to get dns question
@param msg Output DNS message structure (MUST be allocated by caller)
@param buf Pointer of buffer
@param start The start of the whole dns message (SHOULD be given by dns_message_decode function)
@return New buffer pointer
*/
static inline const uint8_t* get_dns_question(dns_message_t* msg, const uint8_t* buf,
                                              const uint8_t* start);

/*
@brief A utility function to get dns domain where it is represented in compression
@param msg Output DNS message structure (MUST be allocated by caller)
@param buf Pointer of buffer
@param start The start of the whole dns message (SHOULD be given by dns_message_decode function)
@return New buffer pointer
*/
static inline const uint8_t* get_dns_domain(dns_message_t* msg, const uint8_t* buf,
                                            const uint8_t* start);

/*
@brief A utility function to get dns answer
@param msg Output DNS message structure (MUST be allocated by caller)
@param buf Pointer of buffer
@param start The start of the whole dns message (SHOULD be given by dns_message_decode function)
@return New buffer pointer
*/
static inline const uint8_t* get_dns_ansewr(dns_message_t* msg, const uint8_t* buf,
                                            const uint8_t* start);

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
#endif