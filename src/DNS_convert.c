#include "../include/DNS_convert.h"

#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

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

void convert_write_bytes(uint8_t** buf, int bytes, uint32_t value) {
    if (bytes == 1) {
        memcpy(*buf, &value, 1);
        *buf += 1;
    } else if (bytes == 2) {
        uint16_t value_to_write = htons((uint16_t)value);
        memcpy(*buf, &value_to_write, 2);
        *buf += 2;
    } else if (bytes == 4) {
        uint32_t value_to_write = htonl((uint32_t)value);
        memcpy(*buf, &value_to_write, 4);
        *buf += 4;
    }
}

static inline uint8_t* get_dns_header(dns_message_t* msg, const uint8_t* buf) {
    msg->header->id = convert_read_bytes(&buf, 2);
    msg->header->flags = convert_read_bytes(&buf, 2);
    msg->header->qdcount = convert_read_bytes(&buf, 2);
    msg->header->ancount = convert_read_bytes(&buf, 2);
    msg->header->nscount = convert_read_bytes(&buf, 2);
    msg->header->arcount = convert_read_bytes(&buf, 2);

    return buf;
}

static inline uint8_t* get_dns_question(dns_message_t* msg, const uint8_t* buf,
                                        const uint8_t* start) {
    int qd_cnt = msg->header->qdcount, i = 0;
    for (i = 0; i < qd_cnt; i++) {
        char name[DNS_RR_NAME_MAX_SIZE];
        dns_question_t* question_ptr = (dns_question_t*)malloc(sizeof(dns_question_t));

        buf = get_dns_domain(msg, buf, start);

        question_ptr->q_name = (char*)malloc(strlen(name) + 1);
        memcpy(question_ptr->q_name, name, strlen(name) + 1);

        question_ptr->q_type = convert_read_bytes(&buf, 2);
        question_ptr->q_class = convert_read_bytes(&buf, 2);

        question_ptr->next = msg->question;
        msg->question = question_ptr;
    }
    return buf;
}

static inline uint8_t* get_dns_domain(dns_message_t* msg, const uint8_t* buf,
                                      const uint8_t* start) {}