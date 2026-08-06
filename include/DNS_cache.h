#ifndef DNS_CACHE_H
#define DNS_CACHE_H

#include <inttypes.h>
#include <time.h>
#define TABLE_MAX_SIZE 1048576

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

/* When non-zero, cache_insert() will skip writing the CACHE_INSERT log
 * record.  Set this around bulk-load paths (e.g. load_cached_dns_file)
 * so that loading a file with ~1M entries does not produce ~1M log
 * lines.  Restore the previous value afterwards so that runtime
 * cache_insert() calls (from cache_answers_from_msg) still log. */
extern int cache_insert_logging_suppressed;
#endif