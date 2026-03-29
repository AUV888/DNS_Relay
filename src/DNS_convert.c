#include "../include/DNS_convert.h"

#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "../include/DNS_struct.h"

uint32_t convert_read_bytes(const uint8_t** buf, int bytes) {
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
    } else
        return 0xFFFFFFFF;
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

static inline const uint8_t* get_dns_header(dns_message_t* msg, const uint8_t* buf) {
    msg->header->id = convert_read_bytes(&buf, 2);
    msg->header->flags = convert_read_bytes(&buf, 2);
    msg->header->qdcount = convert_read_bytes(&buf, 2);
    msg->header->ancount = convert_read_bytes(&buf, 2);
    msg->header->nscount = convert_read_bytes(&buf, 2);
    msg->header->arcount = convert_read_bytes(&buf, 2);

    return buf;
}

static inline const uint8_t* get_dns_question(dns_message_t* msg, const uint8_t* buf,
                                              const uint8_t* start) {
    int qd_cnt = msg->header->qdcount, i = 0;
    for (i = 0; i < qd_cnt; i++) {
        char name[DNS_RR_NAME_MAX_SIZE] = {0};
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

static inline const uint8_t* get_dns_domain(dns_message_t* msg, const uint8_t* buf,
                                            const uint8_t* start) {
    return NULL;
}

static inline const uint8_t* get_dns_ansewr(dns_message_t* msg, const uint8_t* buf,
                                            const uint8_t* start) {
    return NULL;
}

void dns_message_decode(dns_message_t* msg, const uint8_t* buf) {
    const uint8_t* start = buf;
    buf = get_dns_header(msg, buf);
    buf = get_dns_question(msg, buf, start);
    buf = get_dns_ansewr(msg, buf, start);
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
}

static inline uint8_t* set_dns_question(dns_message_t* msg, uint8_t* buf) {
    dns_question_t* q_ptr = msg->question;
    for (int i = 0; i < msg->header->qdcount; i++) {
        buf = set_dns_domain(buf, q_ptr->q_name);
        convert_write_bytes(&buf, 2, q_ptr->q_type);
        convert_write_bytes(&buf, 2, q_ptr->q_class);
        q_ptr = q_ptr->next;
    }
    return buf;
}

static inline uint8_t* set_dns_answer(dns_message_t* msg, uint8_t* buf, uint8_t* ip_addr) {
    dns_resource_record_t* ans_ptr = msg->answer;
    for (int i = 0; i < msg->header->arcount; i++) {
        buf = set_dns_domain(&buf, ans_ptr->name);
        convert_write_bytes(&buf, 2, ans_ptr->rr_class);
        convert_write_bytes(&buf, 4, ans_ptr->ttl);
        convert_write_bytes(&buf, 2, ans_ptr->rd_length);
        for (int j = 0; j < 4; j++) {
            *buf = ip_addr[j];
            buf++;
        }

        ans_ptr = ans_ptr->next;
    }
    return buf;
}

uint8_t* dns_message_encode(dns_message_t* msg, uint8_t* buf, uint8_t* ip_addr) {
    buf = set_dns_header(msg, buf, ip_addr);
    buf = set_dns_question(msg, buf);
    buf = set_dns_answer(msg, buf, ip_addr);
    return buf;
}