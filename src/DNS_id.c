#include "../include/DNS_id.h"

#include <pthread.h>
#include <stdatomic.h>
#include <string.h>

#include "../include/DNS_debug.h"

/* -----------------------------------------------------------------------
 * Sharded ID map.
 *
 * New DNS ID = shard_index * ID_SHARD_SIZE + slot INDEX, still O(1).
 * Every shard owns a slice of the ID space and a mutex that guards its
 * entries and its allocation cursor.
 * ----------------------------------------------------------------------- */
typedef struct id_shard {
    pthread_mutex_t lock; /* guards entries[] and next_slot */
    id_entry_t entries[ID_SHARD_SIZE];
    int next_slot;        /* rotating allocation cursor within this shard */
} id_shard_t;

static id_shard_t id_shards[ID_SHARDS];

/* Lock-free round-robin counter used to pick a shard on insert, so that
 * concurrent inserts spread across shards instead of piling onto one. */
static atomic_uint insert_shard_rr = 0;

/* Guards against double initialization (pthread_mutex_init twice is UB). */
static int id_map_ready = 0;

void id_map_init(void) {
    if (id_map_ready)
        return;
    memset(id_shards, 0, sizeof(id_shards));
    for (int i = 0; i < ID_SHARDS; i++) {
        pthread_mutex_init(&id_shards[i].lock, NULL);
        id_shards[i].next_slot = 0;
    }
    atomic_store(&insert_shard_rr, 0);
    id_map_ready = 1;
    if (debug_mode) {
        log_event_t l = ID_MAP_INIT;
        uint64_t pl = (EVENT_MASK & ((uint64_t)l << 48)) |
            (THREAD_MASK & ((uint64_t)log_thread_id << 32));
        log_write(pl);
    }
}

int id_map_insert(uint16_t original_id, const struct sockaddr_in* client_addr,
                  uint16_t* new_id_output) {
    if (client_addr == NULL || new_id_output == NULL) {
        if (debug_mode) {
            log_event_t l = ID_MAP_INSERT_ARGS_NULL_PTR_ERR;
            uint64_t pl = (EVENT_MASK & ((uint64_t)l << 48)) |
                (THREAD_MASK & ((uint64_t)log_thread_id << 32));
            log_write(pl);
        }
        return 0;
    }

    /* Pick a shard round-robin without taking any lock. */
    unsigned pick = atomic_fetch_add_explicit(&insert_shard_rr, 1u, memory_order_relaxed);
    unsigned shard_idx = pick % ID_SHARDS;
    id_shard_t* sh = &id_shards[shard_idx];

    pthread_mutex_lock(&sh->lock);
    for (int i = 0; i < ID_SHARD_SIZE; i++) {
        int idx = (sh->next_slot + i) % ID_SHARD_SIZE;
        id_entry_t* e = &sh->entries[idx];

        int reusable = !e->used;
        if (!reusable) {
            time_t now = time(NULL);
            if (now - e->send_time > ID_MAP_TIMEOUT)
                reusable = 1;  // expired, mark as reusable
        }

        if (reusable) {
            e->used = 1;
            e->original_id = original_id;
            e->client_addr = *client_addr;
            e->send_time = time(NULL);

            sh->next_slot = (idx + 1) % ID_SHARD_SIZE;
            pthread_mutex_unlock(&sh->lock);

            /* Encode shard + slot into the relayed transaction ID. */
            *new_id_output = (uint16_t)(shard_idx * ID_SHARD_SIZE + idx);
            return 1;
        }
    }
    pthread_mutex_unlock(&sh->lock);

    /* this shard is full and nothing has expired; drop the query */
    if (debug_mode) {
        log_event_t l = ID_MAP_FIND_TIMEOUT_ERR;
        uint64_t pl = (EVENT_MASK & ((uint64_t)l << 48)) |
            (THREAD_MASK & ((uint64_t)log_thread_id << 32));
        log_write(pl);
    }
    return 0;
}

int id_map_find(uint16_t new_id, uint16_t* original_id_out, struct sockaddr_in* client_addr_out) {
    if (new_id >= ID_LIST_SIZE) {
        if (debug_mode) {
            log_event_t l = ID_MAP_FIND_ID_OUT_BOUND_ERR;
            uint64_t pl = (EVENT_MASK & ((uint64_t)l << 48)) |
                (THREAD_MASK & ((uint64_t)log_thread_id << 32));
            log_write(pl);
        }
        return 0;
    }

    id_shard_t* sh = &id_shards[new_id / ID_SHARD_SIZE];
    int slot = new_id % ID_SHARD_SIZE;

    pthread_mutex_lock(&sh->lock);
    id_entry_t* e = &sh->entries[slot];

    if (!e->used) {
        pthread_mutex_unlock(&sh->lock);
        if (debug_mode) {
            log_event_t l = ID_MAP_FIND_USED_ID_ERR;
            uint64_t pl = (EVENT_MASK & ((uint64_t)l << 48)) |
                (THREAD_MASK & ((uint64_t)log_thread_id << 32));
            log_write(pl);
        }
        return 0;
    }
    if (time(NULL) - e->send_time > ID_MAP_TIMEOUT) {
        pthread_mutex_unlock(&sh->lock);
        if (debug_mode) {
            log_event_t l = ID_MAP_FIND_TIMEOUT_ERR;
            uint64_t pl = (EVENT_MASK & ((uint64_t)l << 48)) |
                (THREAD_MASK & ((uint64_t)log_thread_id << 32));
            log_write(pl);
        }
        return 0;
    }

    if (original_id_out)
        *original_id_out = e->original_id;
    if (client_addr_out)
        *client_addr_out = e->client_addr;
    pthread_mutex_unlock(&sh->lock);

    if (debug_mode) {
        log_event_t l = ID_MAP_FIND_SUCCESS;
        uint64_t pl = (EVENT_MASK & ((uint64_t)l << 48)) |
            (THREAD_MASK & ((uint64_t)log_thread_id << 32));
        log_write(pl);
    }
    return 1;
}

int id_map_erase(uint16_t new_id) {
    if (new_id >= ID_LIST_SIZE) {
        if (debug_mode) {
            log_event_t l = ID_MAP_ERASE_ID_OUT_BOUND_ERR;
            uint64_t pl = (EVENT_MASK & ((uint64_t)l << 48)) |
                (THREAD_MASK & ((uint64_t)log_thread_id << 32));
            log_write(pl);
        }
        return 0;
    }

    id_shard_t* sh = &id_shards[new_id / ID_SHARD_SIZE];
    int slot = new_id % ID_SHARD_SIZE;

    pthread_mutex_lock(&sh->lock);
    id_entry_t* e = &sh->entries[slot];

    if (!e->used) {
        // Cannot erase a slot that is not in use
        pthread_mutex_unlock(&sh->lock);
        if (debug_mode) {
            /* The log would be
             * [Timestamp : 8B][ID_MAP_ERASE_ID_MAP_USED_ERR : 2B][Thread : 2B][Info : 4B, low 2B = new_id]
             */
            log_event_t l = ID_MAP_ERASE_ID_MAP_USED_ERR;
            uint64_t pl =
                (EVENT_MASK & ((uint64_t)l << 48)) |
                (THREAD_MASK & ((uint64_t)log_thread_id << 32)) |
                (INFO_MASK & (uint64_t)new_id);
            log_write(pl);
        }
        return 0;
    }

    e->used = 0;
    pthread_mutex_unlock(&sh->lock);

    if (debug_mode) {
        /* The log would be
         * [Timestamp : 8B][ID_MAP_ERASED_SUCCESS : 2B][Thread : 2B][Info : 4B, low 2B = new_id]
         */
        log_event_t l = ID_MAP_ERASED_SUCCESS;
        uint64_t pl =
            (EVENT_MASK & ((uint64_t)l << 48)) |
            (THREAD_MASK & ((uint64_t)log_thread_id << 32)) |
            (INFO_MASK & (uint64_t)new_id);
        log_write(pl);
    }
    return 1;
}

int id_map_sweep_timeout(void) {
    int released = 0;
    time_t now = time(NULL);
    /* Lock shards one at a time; never hold two shard locks at once. */
    for (int s = 0; s < ID_SHARDS; s++) {
        id_shard_t* sh = &id_shards[s];
        pthread_mutex_lock(&sh->lock);
        for (int i = 0; i < ID_SHARD_SIZE; i++) {
            if (sh->entries[i].used && (now - sh->entries[i].send_time > ID_MAP_TIMEOUT)) {
                sh->entries[i].used = 0;
                released++;
            }
        }
        pthread_mutex_unlock(&sh->lock);
    }
    /* The caller controls the sweep frequency (worker 0 only, once per
     * second in multi-threaded mode), so no extra log throttling is
     * needed here. */
    if (debug_mode) {
        /* The log would be
         * [Timestamp : 8B][ID_MAP_SWEEP_TIMEOUT_SUCCESS : 2B][Thread : 2B][release : 4B]
         */
        log_event_t l = ID_MAP_SWEEP_TIMEOUT_SUCCESS;
        uint64_t pl =
            (EVENT_MASK & ((uint64_t)l << 48)) |
            (THREAD_MASK & ((uint64_t)log_thread_id << 32)) |
            (INFO_MASK & (uint64_t)released);
        log_write(pl);
    }
    return released;
}
