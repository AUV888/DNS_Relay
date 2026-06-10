#ifndef DNS_CACHE_H
#define DNS_CACHE_H

#include <inttypes.h>
#include <time.h>
#define TABLE_MAX_SIZE 8192

uint32_t hash(const char* str);

typedef struct HASH_NODE {
    char* domain;
    uint32_t ipv4;
    time_t expire_time;
    struct HASH_NODE* next;
} node;

typedef struct SET {
    node* bucket[TABLE_MAX_SIZE];
    unsigned long size;
} cache_set;

cache_set* create_hset(void);
int cache_init(cache_set* s);
int cache_destroy(cache_set** s);
int cache_insert(cache_set* s, char* src, uint32_t ip, int ttl);
int cache_erase(cache_set* s, char* src);
int cache_clear(cache_set* s);
int cache_find(cache_set* s, char* src, uint32_t* ip_addr_output);
unsigned long cache_size(cache_set* s);
#endif