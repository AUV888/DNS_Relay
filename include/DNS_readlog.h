#ifndef DNS_READLOG_H
#define DNS_READLOG_H

#include <stdio.h>

#include "DNS_debug.h"

/* Prints the "[main]"/"[disp]"/"[pthN]" writer tag followed by the event
 * name.  thread_id is LOG_THREAD_ID_MAIN for the main thread,
 * LOG_THREAD_ID_DISPATCHER for the dispatcher, otherwise the 0-based
 * worker index. */
void read_data(log_event_t l, uint16_t thread_id);
#endif