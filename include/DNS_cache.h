#ifndef DNS_CACHE_H
#define DNS_CACHE_H

#include <inttypes.h>
#include <pthread.h>
#include <time.h>
#define TABLE_MAX_SIZE 1048576

/* The cache is split into CACHE_SHARDS independent shards so that
 * concurrent workers contend on smaller, independent locks.
 *
 * TABLE_MAX_SIZE (2^20) = CACHE_SHARDS (2^4) * SHARD_BUCKETS (2^16), so a
 * full 20-bit hash value splits losslessly:
 *     shard index        = hash / SHARD_BUCKETS   (high 4 bits)
 *     intra-shard bucket = hash % SHARD_BUCKETS   (low 16 bits)
 *
 * The public hash() contract (returns hash % TABLE_MAX_SIZE) is unchanged.
 */
#define CACHE_SHARDS 16
#define SHARD_BUCKETS (TABLE_MAX_SIZE / CACHE_SHARDS)

uint32_t hash(const char* str);

typedef struct HASH_NODE {
    char* domain;
    uint32_t ipv4;
    time_t expire_time;
    struct HASH_NODE* next;
} node;

/* One shard: a chained hash table guarded by its own mutex.  A plain
 * mutex (not a rwlock) is required because cache_find() performs lazy
 * deletion of expired entries, i.e. even the lookup path mutates the
 * bucket list. */
typedef struct cache_shard {
    pthread_mutex_t lock; /* guards bucket[] and size */
    node* bucket[SHARD_BUCKETS];
    unsigned long size;
} cache_shard_t;

typedef struct SET {
    cache_shard_t shards[CACHE_SHARDS];
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
 * cache_insert() calls (from cache_answers_from_msg) still log.
 *
 * Thread-local: bulk-load runs on the main thread before workers are
 * spawned, so toggling it there must not disturb the workers. */
extern _Thread_local int cache_insert_logging_suppressed;
#endif