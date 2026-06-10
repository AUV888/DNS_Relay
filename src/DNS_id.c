#include "../include/DNS_id.h"

#include <string.h>

#include "../include/DNS_debug.h"

/* New DNS ID = slot INDEX, O(1)
 */
static id_entry_t id_map[ID_LIST_SIZE];

static int next_slot = 0;

void id_map_init(void) {
    memset(id_map, 0, sizeof(id_map));
    next_slot = 0;
}

int id_map_insert(uint16_t original_id, const struct sockaddr_in* client_addr,
                  uint16_t* new_id_output) {
    if (client_addr == NULL || new_id_output == NULL)
        return 0;

    for (int i = 0; i < ID_LIST_SIZE; i++) {
        int idx = (next_slot + i) % ID_LIST_SIZE;

        int reusable = !id_map[idx].used;
        if (!reusable) {
            time_t now = time(NULL);
            if (now - id_map[idx].send_time > ID_MAP_TIMEOUT)
                reusable = 1;  // expired, mark as reusable
        }

        if (reusable) {
            id_map[idx].used = 1;
            id_map[idx].original_id = original_id;
            id_map[idx].client_addr = *client_addr;
            id_map[idx].send_time = time(NULL);

            *new_id_output = (uint16_t)idx;
            next_slot = (idx + 1) % ID_LIST_SIZE;
            return 1;
        }
    }
    // table full and nothing has expired
    return 0;
}

int id_map_find(uint16_t new_id, uint16_t* original_id_out, struct sockaddr_in* client_addr_out) {
    if (new_id >= ID_LIST_SIZE)
        return 0;
    if (!id_map[new_id].used)
        return 0;
    if (time(NULL) - id_map[new_id].send_time > ID_MAP_TIMEOUT)
        return 0;

    if (original_id_out)
        *original_id_out = id_map[new_id].original_id;
    if (client_addr_out)
        *client_addr_out = id_map[new_id].client_addr;
    return 1;
}

int id_map_erase(uint16_t new_id) {
    if (new_id >= ID_LIST_SIZE)
        return 0;
    if (!id_map[new_id].used)
        return 0;

    id_map[new_id].used = 0;
    return 1;
}

int id_map_sweep_timeout(void) {
    int released = 0;
    time_t now = time(NULL);
    for (int i = 0; i < ID_LIST_SIZE; i++) {
        if (id_map[i].used && (now - id_map[i].send_time > ID_MAP_TIMEOUT)) {
            id_map[i].used = 0;
            released++;
        }
    }
    return released;
}
