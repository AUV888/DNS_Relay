#include "../include/DNS_convert.h"

#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "../include/DNS_struct.h"
#include "../include/DNS_util.h"

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

static inline uint8_t* get_dns_header(dns_message_t* msg, uint8_t* buf) {
    msg->header->id = convert_read_bytes(&buf, 2);
    msg->header->flags = convert_read_bytes(&buf, 2);
    msg->header->qdcount = convert_read_bytes(&buf, 2);
    msg->header->ancount = convert_read_bytes(&buf, 2);
    msg->header->nscount = convert_read_bytes(&buf, 2);
    msg->header->arcount = convert_read_bytes(&buf, 2);

    return buf;
}

static inline uint8_t* get_dns_question(dns_message_t* msg, uint8_t* buf, uint8_t* start) {
    int qd_cnt = msg->header->qdcount, i = 0, idx = 0;
    for (i = 0; i < qd_cnt; i++) {
        char name[DNS_RR_NAME_MAX_SIZE] = {0};
        dns_question_t* question_ptr = (dns_question_t*)malloc(sizeof(dns_question_t));

        buf = get_dns_domain(name, &idx, &buf, start);

        question_ptr->q_name = (char*)malloc(strlen(name) + 1);
        memcpy(question_ptr->q_name, name, strlen(name) + 1);

        question_ptr->q_type = convert_read_bytes(&buf, 2);
        question_ptr->q_class = convert_read_bytes(&buf, 2);

        question_ptr->next = msg->question;
        msg->question = question_ptr;
    }
    return buf;
}

static inline uint8_t* get_dns_domain(char* result, int* idx, uint8_t** buf, uint8_t* start) {
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
        // read char
        if (state == READING_DATA) {
            uint8_t ch = convert_read_bytes(buf, 1);
            if (ch == 0) {             // domain end
                if (stack.top >= 0) {  // if stack is not empty, jump back
                    *buf = ui8_ptr_stack_pop(&stack);
                    state = READING_LENGTH;
                    continue;
                } else {
                    return *buf;  // end of the procedures
                }
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
                uint16_t offset = (uint16_t)convert_read_bytes(buf, 2);
                offset &= 0x3FFF;
                if (offset >= *buf - start) {
                    // handle error and exit
                    return NULL;
                }
                if (jmp_cnt >= MAX_DNS_JUMP) {
                    // handle error: too many jumps
                    return NULL;
                }
                // push buf and jump
                ui8_ptr_stack_push(&stack, *buf);
                *buf = start + offset;
                jmp_cnt++;
                continue;  // continue from new position
            }
            // is a value or end of domain
            else {
                uint8_t length = (uint8_t)convert_read_bytes(buf, 1);
                if (length == 0) {         // end of domain
                    if (stack.top >= 0) {  // if stack is not empty, jump back
                        *buf = ui8_ptr_stack_pop(&stack);
                        continue;
                    } else {
                        return *buf;  // end of the procedure
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

static inline uint8_t* get_dns_answer(dns_message_t* msg, uint8_t* buf, uint8_t* start) {
    for (int i = 0; i < msg->header->ancount; i++) {
        char name[DNS_RR_NAME_MAX_SIZE] = {0};
        int idx = 0;
        dns_resource_record_t* rr_ptr =
            (dns_resource_record_t*)malloc(sizeof(dns_resource_record_t));
        if (rr_ptr == NULL) {
            // handle error
        }
        buf = get_dns_domain(name, &idx, &buf, start);
        rr_ptr->name = (char*)malloc(strlen(name));
        memcpy(rr_ptr->name, name, strlen(name) + 1);

        rr_ptr->type = convert_read_bytes(&buf, 2);
        rr_ptr->rr_class = convert_read_bytes(&buf, 2);
        rr_ptr->ttl = convert_read_bytes(&buf, 4);
        rr_ptr->rd_length = convert_read_bytes(&buf, 2);

        dns_type_t type = (dns_type_t)rr_ptr->type;
        switch (type) {
            case DNS_TYPE_A: {
                for (int j = 0; j < 4; j++) {
                    rr_ptr->rd_data.a_record.ip_addr[j] = (uint8_t)convert_read_bytes(&buf, 1);
                }
                break;
            }
            case DNS_TYPE_AAAA: {
                for (int j = 0; j < 16; j++) {
                    rr_ptr->rd_data.a_record.ip_addr[j] = (uint8_t)convert_read_bytes(&buf, 1);
                }
                break;
            }
            case DNS_TYPE_SOA: {
                char mname[DNS_RR_NAME_MAX_SIZE] = {0}, rname[DNS_RR_NAME_MAX_SIZE] = {0};
                int m_idx = 0, r_idx = 0;
                buf = get_dns_domain(mname, &m_idx, &buf, start);
                buf = get_dns_domain(rname, &r_idx, &buf, start);

                rr_ptr->rd_data.soa_record.mname = (char*)malloc(strlen(mname) + 1);
                memcpy(rr_ptr->rd_data.soa_record.mname, mname, strlen(mname) + 1);

                rr_ptr->rd_data.soa_record.rname = (char*)malloc(strlen(rname) + 1);
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
                buf = get_dns_domain(cname, &c_idx, &buf, start);
                rr_ptr->rd_data.cname_record.cname = (char*)malloc(strlen(cname) + 1);
                memcpy(rr_ptr->rd_data.cname_record.cname, cname, strlen(cname) + 1);
                break;
            }
            case DNS_TYPE_MX: {
                rr_ptr->rd_data.mx_record.preference = (uint16_t)convert_read_bytes(&buf, 2);
                char exchange[DNS_RR_NAME_MAX_SIZE] = {0};
                int e_idx = 0;
                buf = get_dns_domain(exchange, &e_idx, &buf, start);
                rr_ptr->rd_data.mx_record.exchange = (char*)malloc(strlen(exchange) + 1);
                memcpy(rr_ptr->rd_data.mx_record.exchange, exchange, strlen(exchange) + 1);
                break;
            }
            case DNS_TYPE_TXT: {
                rr_ptr->rd_data.txt_record.text = (char*)malloc(rr_ptr->rd_length);
                memcpy(rr_ptr->rd_data.txt_record.text, buf, rr_ptr->rd_length);
                buf += rr_ptr->rd_length;
                break;
            }
            default: {
                buf += rr_ptr->rd_length;
                break;
            }
        }
        rr_ptr->next = msg->answer;
        msg->answer = rr_ptr;
    }
    return buf;
}

void dns_message_decode(dns_message_t* msg, uint8_t* buf) {
    uint8_t* start = buf;
    buf = get_dns_header(msg, buf);
    buf = get_dns_question(msg, buf, start);
    buf = get_dns_answer(msg, buf, start);
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
        buf = set_dns_domain(buf, ans_ptr->name);
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