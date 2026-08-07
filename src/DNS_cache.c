#include "../include/DNS_cache.h"

#include <stdlib.h>
#include <string.h>

#include "../include/DNS_debug.h"

/* Thread-local flag that suppresses the CACHE_INSERT log inside
 * cache_insert().  Bulk-loading (load_cached_dns_file) runs on the main
 * thread before any worker is created, so toggling the main thread's
 * copy never affects the workers' copies — exactly what we want: bulk
 * inserts stay silent, runtime inserts still log.  A plain global with
 * save/restore would be racy once workers exist. */
_Thread_local int cache_insert_logging_suppressed = 0;

uint32_t hash(const char* str) {
    uint32_t hash = 2166136261u;

    while (*str) {
        hash ^= (uint8_t)(*str++);
        hash *= 16777619u;
    }

    return hash % TABLE_MAX_SIZE;
}

/* -----------------------------------------------------------------------
 * Shard selection helpers.
 *
 * hash() returns a value in [0, TABLE_MAX_SIZE).  Because TABLE_MAX_SIZE
 * = CACHE_SHARDS * SHARD_BUCKETS and both factors are powers of two, the
 * value splits cleanly into a shard index (high bits) and an intra-shard
 * bucket index (low bits).  Compilers turn these into a shift and a mask.
 * ----------------------------------------------------------------------- */
static inline unsigned shard_index(uint32_t h) { return (unsigned)(h / SHARD_BUCKETS); }

static inline uint32_t shard_bucket(uint32_t h) { return h % SHARD_BUCKETS; }

cache_set* create_hset(void) {
    cache_set* dest = (cache_set*)malloc(sizeof(cache_set));
    if (debug_mode) {
        log_event_t l = dest ? CREATE_HSET_SUCCESS : CREATE_HSET_ERR;
        uint64_t pl = (EVENT_MASK & ((uint64_t)l << 48)) |
            (THREAD_MASK & ((uint64_t)log_thread_id << 32));
        log_write(pl);
    }
    return dest;
}
int cache_init(cache_set* s) {
    if (!s)
        return 0;
    for (int i = 0; i < CACHE_SHARDS; i++) {
        cache_shard_t* sh = &s->shards[i];
        memset(sh->bucket, 0, sizeof(sh->bucket));
        sh->size = 0;
        pthread_mutex_init(&sh->lock, NULL);
    }
    if (debug_mode) {
        log_event_t l = CACHE_INIT;
        uint64_t pl = (EVENT_MASK & ((uint64_t)l << 48)) |
            (THREAD_MASK & ((uint64_t)log_thread_id << 32));
        log_write(pl);
    }
    return 1;
}
int cache_destroy(cache_set** s) {
    if (!s || !(*s))
        return 0;
    for (int i = 0; i < CACHE_SHARDS; i++) {
        cache_shard_t* sh = &(*s)->shards[i];
        for (int b = 0; b < SHARD_BUCKETS; b++) {
            node* cur = sh->bucket[b];
            while (cur) {
                node* tmp = cur->next;
                free(cur->domain);
                free(cur);
                cur = tmp;
            }
        }
        pthread_mutex_destroy(&sh->lock);
    }
    free(*s);
    *s = NULL;
    if (debug_mode) {
        log_event_t l = CACHE_DESTROY;
        uint64_t pl = (EVENT_MASK & ((uint64_t)l << 48)) |
            (THREAD_MASK & ((uint64_t)log_thread_id << 32));
        log_write(pl);
    }
    return 1;
}
int cache_insert(cache_set* s, char* src, uint32_t ip, int ttl) {
    if (!s || !src || ttl <= 0)
        return 0;

    uint32_t h = hash(src);
    cache_shard_t* sh = &s->shards[shard_index(h)];
    uint32_t b = shard_bucket(h);

    int inserted_new_node = 0;

    pthread_mutex_lock(&sh->lock);
    node* cur = sh->bucket[b];

    while (cur) {
        if (strcasecmp(cur->domain, src) == 0) {
            /* Refresh an existing entry in place.  (The old code had two
             * branches here that did exactly the same thing.) */
            cur->ipv4 = ip;
            cur->expire_time = time(NULL) + ttl;
            pthread_mutex_unlock(&sh->lock);
            return 1;
        }
        cur = cur->next;
    }

    node* n = (node*)malloc(sizeof(node));
    if (!n) {
        pthread_mutex_unlock(&sh->lock);
        return 0;
    }

    n->domain = (char*)malloc(strlen(src) + 1);
    if (!n->domain) {
        free(n);
        pthread_mutex_unlock(&sh->lock);
        return 0;
    }

    strcpy(n->domain, src);
    n->ipv4 = ip;
    n->expire_time = time(NULL) + ttl;

    n->next = sh->bucket[b];
    sh->bucket[b] = n;
    sh->size++;
    inserted_new_node = 1;
    pthread_mutex_unlock(&sh->lock);

    /* Log outside the lock; the log file has its own serialization. */
    if (inserted_new_node && debug_mode && !cache_insert_logging_suppressed) {
        log_event_t l = CACHE_INSERT;
        uint64_t pl = (EVENT_MASK & ((uint64_t)l << 48)) |
            (THREAD_MASK & ((uint64_t)log_thread_id << 32));
        log_write(pl);
    }
    return 1;
}

int cache_erase(cache_set* s, char* src) {
    if (!s || !src)
        return 0;

    uint32_t h = hash(src);
    cache_shard_t* sh = &s->shards[shard_index(h)];
    uint32_t b = shard_bucket(h);

    pthread_mutex_lock(&sh->lock);
    node* cur = sh->bucket[b];
    node* prev = NULL;

    while (cur) {
        if (strcasecmp(cur->domain, src) == 0) {
            if (prev)
                prev->next = cur->next;
            else
                sh->bucket[b] = cur->next;

            free(cur->domain);
            free(cur);
            sh->size--;
            pthread_mutex_unlock(&sh->lock);
            if (debug_mode) {
                log_event_t l = CACHE_ERASE;
                uint64_t pl = (EVENT_MASK & ((uint64_t)l << 48)) |
                    (THREAD_MASK & ((uint64_t)log_thread_id << 32));
                log_write(pl);
            }
            return 1;
        }
        prev = cur;
        cur = cur->next;
    }
    pthread_mutex_unlock(&sh->lock);
    return 0;
}

int cache_clear(cache_set* s) {
    if (!s)
        return 0;

    for (int i = 0; i < CACHE_SHARDS; i++) {
        cache_shard_t* sh = &s->shards[i];
        pthread_mutex_lock(&sh->lock);
        for (int b = 0; b < SHARD_BUCKETS; b++) {
            node* cur = sh->bucket[b];
            while (cur) {
                node* tmp = cur->next;
                free(cur->domain);
                free(cur);
                cur = tmp;
            }
            sh->bucket[b] = NULL;
        }
        sh->size = 0;
        pthread_mutex_unlock(&sh->lock);
    }
    if (debug_mode) {
        log_event_t l = CACHE_CLEAR;
        uint64_t pl = (EVENT_MASK & ((uint64_t)l << 48)) |
            (THREAD_MASK & ((uint64_t)log_thread_id << 32));
        log_write(pl);
    }
    return 1;
}

int cache_find(cache_set* s, char* src, uint32_t* ip_addr_output) {
    if (!s || !src || !ip_addr_output)
        return 0;
    uint32_t h = hash(src);
    cache_shard_t* sh = &s->shards[shard_index(h)];
    uint32_t b = shard_bucket(h);

    uint32_t found_ip = 0;

    pthread_mutex_lock(&sh->lock);
    node* cur = sh->bucket[b];
    node* prev = NULL;
    while (cur) {
        if (strcasecmp(cur->domain, src) == 0) {
            time_t now = time(NULL);
            if (cur->expire_time > now) {
                /* Copy the answer out, drop the lock, then log. */
                found_ip = cur->ipv4;
                pthread_mutex_unlock(&sh->lock);
                *ip_addr_output = found_ip;
                if (debug_mode) {
                    /* The whole CACHE_FIND_SRC / raw-bytes / CACHE_FIND_HASH /
                     * CACHE_FIND sequence is emitted under ONE lock
                     * acquisition: the parser relies on the domain bytes
                     * following CACHE_FIND_SRC immediately, so no other
                     * thread's record may interleave in the middle. */
                    log_lock();

                    /* First, write the domain we want to find, e.g. www.google.com
                     * The log would be
                     * [Timestamp : 8B][CACHE_FIND_SRC : 2B][Thread : 2B][Length of domain : 4B]
                     * ['w' 'w' 'w' '.' 'g' 'o' 'o' 'g' 'l' 'e' '.' 'c' 'o' 'm']
                     */
                    log_event_t l = CACHE_FIND_SRC;
                    uint32_t src_len = (uint32_t)strlen(src);
                    uint64_t pl =
                        (EVENT_MASK & ((uint64_t)l << 48)) |
                        (THREAD_MASK & ((uint64_t)log_thread_id << 32)) |
                        (INFO_MASK & (uint64_t)src_len);
                    log_write_nolock(pl);
                    log_write_bytes_nolock(src, src_len);

                    /* Second, write the hash of the domain
                     * The log would be
                     * [Timestamp : 8B][CACHE_FIND_HASH : 2B][Thread : 2B][hash code : 4B]
                     */
                    l = CACHE_FIND_HASH;
                    pl = (EVENT_MASK & ((uint64_t)l << 48)) |
                         (THREAD_MASK & ((uint64_t)log_thread_id << 32)) |
                         (INFO_MASK & h);
                    log_write_nolock(pl);

                    /* Last, write the IPv4 of the domain
                     * The log would be
                     * [Timestamp : 8B][CACHE_FIND : 2B][Thread : 2B][IPv4 : 4B]
                     */
                    l = CACHE_FIND;
                    pl = (EVENT_MASK & ((uint64_t)l << 48)) |
                         (THREAD_MASK & ((uint64_t)log_thread_id << 32));
                    pl |= INFO_MASK & found_ip;
                    log_write_nolock(pl);

                    log_unlock();
                }
                return 1;
            } else {
                /* Expired: lazy deletion of this node. */
                if (prev)
                    prev->next = cur->next;
                else
                    sh->bucket[b] = cur->next;

                free(cur->domain);
                free(cur);
                sh->size--;
                pthread_mutex_unlock(&sh->lock);
                return 0;
            }
        }
        prev = cur;
        cur = cur->next;
    }
    pthread_mutex_unlock(&sh->lock);
    return 0;
}

unsigned long cache_size(cache_set* s) {
    if (!s)
        return 0;
    unsigned long total = 0;
    for (int i = 0; i < CACHE_SHARDS; i++) {
        pthread_mutex_lock(&s->shards[i].lock);
        total += s->shards[i].size;
        pthread_mutex_unlock(&s->shards[i].lock);
    }
    return total;
}
