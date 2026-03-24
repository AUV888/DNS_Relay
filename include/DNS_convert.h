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
#endif