#ifndef DNS_STRUCT_H
#define DNS_STRUCT_H

#include <stdint.h>

#define DNS_STRING_MAX_SIZE 8192
#define DNS_RR_NAME_MAX_SIZE 512

#define DNS_QR_QUERY 0
#define DNS_QR_ANSWER 1

#define DNS_OPCODE_QUERY 0
#define DNS_OPCODE_IQUERY 1
#define DNS_OPCODE_STATUS 2

enum dns_type {
    DNS_TYPE_A = 1,
    DNS_TYPE_NS = 2,
    DNS_TYPE_CNAME = 5,
    DNS_TYPE_SOA = 6,
    DNS_TYPE_PTR = 12,
    DNS_TYPE_HINFO = 13,
    DNS_TYPE_MINFO = 14,
    DNS_TYPE_MX = 15,
    DNS_TYPE_TXT = 16,
    DNS_TYPE_AAAA = 28
};
typedef dns_type dns_type_t;

#define DNS_CLASS_IN 1

#define DNS_RCODE_OK 0
#define DNS_RCODE_NXDOMAIN 3

#define DNS_FLAG_QR 0x8000
#define DNS_FLAG_OPCODE 0x7800
#define DNS_FLAG_AA 0x0400
#define DNS_FLAG_TC 0x0200
#define DNS_FLAG_RD 0x0100
#define DNS_FLAG_RA 0x0080
#define DNS_FLAG_Z 0x0070
#define DNS_FLAG_RCODE 0x000F

#define DNS_GET_QR(flags) (((flags) & DNS_FLAG_QR) >> 15)
#define DNS_GET_OPCODE(flags) (((flags) & DNS_FLAG_OPCODE) >> 11)
#define DNS_GET_AA(flags) (((flags) & DNS_FLAG_AA) >> 10)
#define DNS_GET_TC(flags) (((flags) & DNS_FLAG_TC) >> 9)
#define DNS_GET_RD(flags) (((flags) & DNS_FLAG_RD) >> 8)
#define DNS_GET_RA(flags) (((flags) & DNS_FLAG_RA) >> 7)
#define DNS_GET_Z(flags) (((flags) & DNS_FLAG_Z) >> 4)
#define DNS_GET_RCODE(flags) ((flags) & DNS_FLAG_RCODE)

#define DNS_SET_QR(flags, val) (flags) = ((flags) & ~DNS_FLAG_QR) | (((val) & 0x1) << 15)
#define DNS_SET_OPCODE(flags, val) (flags) = ((flags) & ~DNS_FLAG_OPCODE) | (((val) & 0xF) << 11)
#define DNS_SET_AA(flags, val) (flags) = ((flags) & ~DNS_FLAG_AA) | (((val) & 0x1) << 10)
#define DNS_SET_TC(flags, val) (flags) = ((flags) & ~DNS_FLAG_TC) | (((val) & 0x1) << 9)
#define DNS_SET_RD(flags, val) (flags) = ((flags) & ~DNS_FLAG_RD) | (((val) & 0x1) << 8)
#define DNS_SET_RA(flags, val) (flags) = ((flags) & ~DNS_FLAG_RA) | (((val) & 0x1) << 7)
#define DNS_SET_Z(flags, val) (flags) = ((flags) & ~DNS_FLAG_Z) | (((val) & 0x7) << 4)
#define DNS_SET_RCODE(flags, val) (flags) = ((flags) & ~DNS_FLAG_RCODE) | ((val) & 0xF)

#pragma pack(push, 1)
struct dns_header {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};
#pragma pack(pop)
typedef struct dns_header dns_header_t;

struct dns_question {
    char* q_name;
    uint16_t q_type;
    uint16_t q_class;
    struct dns_question* next;
};
typedef struct dns_question dns_question_t;

union resource_data {
    struct {
        uint8_t ip_addr[4];
    } a_record;
    struct {
        uint8_t ip_addr[16];
    } aaaa_record;
    struct {
        char* mname;
        char* rname;
        uint32_t serial;
        uint32_t refresh;
        uint32_t retry;
        uint32_t expire;
        uint32_t minimum;
    } soa_record;

    struct {
        char* cname;
    } cname_record;

    struct {
        uint16_t preference;
        char* exchange;
    } mx_record;

    struct {
        char* text;
    } txt_record;
};
typedef union resource_data resource_data_t;

struct dns_resource_record {
    char* name;
    uint16_t type;
    uint16_t rr_class;
    uint32_t ttl;
    uint16_t rd_length;
    resource_data_t rd_data;
    struct dns_resource_record* next;
};
typedef struct dns_resource_record dns_resource_record_t;

struct dns_message {
    dns_header_t* header;
    dns_question_t* question;
    dns_resource_record_t* answer;
    dns_resource_record_t* authority;
    dns_resource_record_t* additional;
};
typedef struct dns_message dns_message_t;
#endif