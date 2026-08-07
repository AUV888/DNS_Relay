#ifndef DNS_ID_H
#define DNS_ID_H

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <sys/socket.h>
#include <time.h>

#include "DNS_server.h"

#define ID_MAP_TIMEOUT 5

/* The ID map is split into ID_SHARDS independent shards, each guarded by
 * its own mutex, so concurrent workers contend on smaller locks.
 *
 * A relayed (new) DNS transaction ID still encodes the slot position:
 *     new_id = shard_index * ID_SHARD_SIZE + slot
 * The value range stays [0, ID_LIST_SIZE), so any worker that receives an
 * upstream reply can locate the owning shard of that ID in O(1) without
 * any cross-shard search.
 */
#define ID_SHARDS 16
#define ID_SHARD_SIZE (ID_LIST_SIZE / ID_SHARDS)

typedef struct id_entry {
    char used;                       // 1 = slot in use, 0 = free
    uint16_t original_id;            // the ID the client put in its query
    struct sockaddr_in client_addr;  // where to send the answer back
    time_t send_time;                // when we forwarded the query (for timeout)
} id_entry_t;

/*@brief Initialize the global ID-mapping table.
 *       Must be called once at program start-up.
 */
void id_map_init(void);

/*@brief Allocate a free slot and store a mapping for an in-flight query.
 *
 * @param original_id   the ID found in the client's query
 * @param client_addr   address of the client (will be copied)
 * @param new_id_output OUT: the new ID that should be written into the
 *                     packet forwarded to the upstream DNS server.
 *
 * @return 1 on success, 0 if the table is full.
 */
int id_map_insert(uint16_t original_id, const struct sockaddr_in* client_addr,
                  uint16_t* new_id_output);

/*@brief Look up a mapping by the new (relayed) ID.
 *       Does NOT remove the entry.
 *
 * @param new_id           the ID found in the upstream answer
 * @param original_id_out  OUT: the original client ID
 * @param client_addr_out  OUT: the original client address
 *
 * @return 1 if found and not expired, 0 otherwise.
 */
int id_map_find(uint16_t new_id, uint16_t* original_id_out, struct sockaddr_in* client_addr_out);

/*@brief Free the slot identified by new_id.
 *       Should be called after the answer has been sent back to the client.
 *
 * @return 1 if the slot was used and is now released, 0 if it was already free.
 */
int id_map_erase(uint16_t new_id);

/*@brief Sweep the table and release every slot whose send_time is older
 *       than ID_MAP_TIMEOUT seconds.
 *       Should be called periodically from the main event loop.
 *
 * @return number of slots released.
 */
int id_map_sweep_timeout(void);

#endif
