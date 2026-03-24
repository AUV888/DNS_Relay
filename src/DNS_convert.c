#include "../include/DNS_convert.h"

#include <string.h>

#include "../include/DNS_struct.h"

uint32_t convert_read_bytes(uint8_t** buf, int bytes) {
    if (bytes == 1) {
        uint8_t val;
        memcpy(&val, *buf, 1);
        *buf += 1;
        return val;
    } else if (bytes == 2) {
        uint16_t val;
        memcpy(&val, *buf, 2);
        *buf += 2;
        return ntohs(val);
    } else if (bytes == 4) {
        uint32_t val;
        memcpy(&val, *buf, 4);
        *buf += 4;
        return ntohl(val);
    }
}