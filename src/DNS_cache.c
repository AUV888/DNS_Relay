#include "../include/DNS_cache.h"

#include <stdlib.h>
#include <string.h>

#include "../include/DNS_debug.h"

/* Global flag that suppresses the CACHE_INSERT log inside cache_insert().
 * Set to non-zero by bulk-load paths (e.g. load_cached_dns_file) to avoid
 * writing one log line per entry when loading a large pre-cached file. */
int cache_insert_logging_suppressed = 0;

uint32_t hash(const char* str) {
    uint32_t hash = 2166136261u;

    while (*str) {
        hash ^= (uint8_t)(*str++);
        hash *= 16777619u;
    }

    return hash % TABLE_MAX_SIZE;
}

cache_set* create_hset(void) {
    cache_set* dest = (cache_set*)malloc(sizeof(cache_set));
    if (debug_mode) {
        log_event_t l = dest ? CREATE_HSET_SUCCESS : CREATE_HSET_ERR;
        uint64_t pl = EVENT_MASK & ((uint64_t)l << 48);
        log_write(pl);
    }
    return dest;
}
int cache_init(cache_set* s) {
    if (!s)
        return 0;
    memset(s->bucket, 0, sizeof(s->bucket));
    s->size = 0;
    if (debug_mode) {
        log_event_t l = CACHE_INIT;
        uint64_t pl = EVENT_MASK & ((uint64_t)l << 48);
        log_write(pl);
    }
    return 1;
}
int cache_destroy(cache_set** s) {
    if (!s || !(*s))
        return 0;
    for (int i = 0; i < TABLE_MAX_SIZE; i++) {
        node* cur = (*s)->bucket[i];
        while (cur) {
            node* tmp = cur->next;
            free(cur->domain);
            free(cur);
            cur = tmp;
        }
    }
    (*s)->size = 0;
    free(*s);
    *s = NULL;
    if (debug_mode) {
        log_event_t l = CACHE_DESTROY;
        uint64_t pl = EVENT_MASK & ((uint64_t)l << 48);
        log_write(pl);
    }
    return 1;
}
int cache_insert(cache_set* s, char* src, uint32_t ip, int ttl) {
    if (!s || !src || ttl <= 0)
        return 0;

    uint32_t h = hash(src);
    node* cur = s->bucket[h];

    while (cur) {
        if (strcasecmp(cur->domain, src) == 0) {
            time_t now = time(NULL);
            if (cur->ipv4 == ip) {
                cur->expire_time = now + ttl;
            } else {
                cur->ipv4 = ip;
                cur->expire_time = now + ttl;
            }
            return 1;
        }
        cur = cur->next;
    }

    node* n = (node*)malloc(sizeof(node));
    if (!n)
        return 0;

    n->domain = (char*)malloc(strlen(src) + 1);
    if (!n->domain) {
        free(n);
        return 0;
    }

    strcpy(n->domain, src);
    n->ipv4 = ip;
    n->expire_time = time(NULL) + ttl;

    n->next = s->bucket[h];
    s->bucket[h] = n;
    s->size++;
    if (debug_mode && !cache_insert_logging_suppressed) {
        log_event_t l = CACHE_INSERT;
        uint64_t pl = EVENT_MASK & ((uint64_t)l << 48);
        log_write(pl);
    }
    return 1;
}

int cache_erase(cache_set* s, char* src) {
    if (!s || !src)
        return 0;

    uint32_t h = hash(src);
    node* cur = s->bucket[h];
    node* prev = NULL;

    while (cur) {
        if (strcasecmp(cur->domain, src) == 0) {
            if (prev)
                prev->next = cur->next;
            else
                s->bucket[h] = cur->next;

            free(cur->domain);
            free(cur);
            s->size--;
            if (debug_mode) {
                log_event_t l = CACHE_ERASE;
                uint64_t pl = EVENT_MASK & ((uint64_t)l << 48);
                log_write(pl);
            }
            return 1;
        }
        prev = cur;
        cur = cur->next;
    }
    return 0;
}

int cache_clear(cache_set* s) {
    if (!s)
        return 0;

    for (int i = 0; i < TABLE_MAX_SIZE; i++) {
        node* cur = s->bucket[i];
        while (cur) {
            node* tmp = cur->next;
            free(cur->domain);
            free(cur);
            cur = tmp;
        }
        s->bucket[i] = NULL;
    }
    s->size = 0;
    if (debug_mode) {
        log_event_t l = CACHE_CLEAR;
        uint64_t pl = EVENT_MASK & ((uint64_t)l << 48);
        log_write(pl);
    }
    return 1;
}

int cache_find(cache_set* s, char* src, uint32_t* ip_addr_output) {
    if (!s || !src || !ip_addr_output)
        return 0;
    uint32_t h = hash(src);
    node* cur = s->bucket[h];
    node* prev = NULL;
    while (cur) {
        if (strcasecmp(cur->domain, src) == 0) {
            time_t now = time(NULL);
            if (cur->expire_time > now) {
                *ip_addr_output = cur->ipv4;
                if (debug_mode) {
                    /* First, write the domain we want to find, e.g. www.google.com
                     * The log would be
                     * [Timestamp : 8B][CACHE_FIND_SRC : 2B][NULL : 2B][Length of domain : 4B]
                     * ['w' 'w' 'w' '.' 'g' 'o' 'o' 'g' 'l' 'e' '.' 'c' 'o' 'm']
                     */
                    log_event_t l = CACHE_FIND_SRC;
                    uint32_t src_len = (uint32_t)strlen(src);
                    uint64_t pl =
                        (EVENT_MASK & ((uint64_t)l << 48)) | (INFO_MASK & (uint64_t)src_len);
                    log_write(pl);
                    log_write_bytes(src, src_len);

                    /* Second, write the hash of the domain
                     * The log would be
                     * [Timestamp : 8B][CACHE_FIND_HASH : 2B][NULL : 2B][hash code : 4B]
                     */
                    l = CACHE_FIND_HASH;
                    pl = (EVENT_MASK & ((uint64_t)l << 48)) | (INFO_MASK & h);
                    log_write(pl);

                    /* Last, write the IPv4 of the domain
                     * The log would be
                     * [Timestamp : 8B][CACHE_FIND : 2B][NULL : 2B][IPv4 : 4B]
                     */
                    l = CACHE_FIND;
                    pl = EVENT_MASK & ((uint64_t)l << 48);
                    pl |= INFO_MASK & cur->ipv4;
                    log_write(pl);
                }
                return 1;
            } else {
                if (prev)
                    prev->next = cur->next;
                else
                    s->bucket[h] = cur->next;

                free(cur->domain);
                free(cur);
                s->size--;
                return 0;
            }
        }
        prev = cur;
        cur = cur->next;
    }
    return 0;
}

unsigned long cache_size(cache_set* s) { return s->size; }