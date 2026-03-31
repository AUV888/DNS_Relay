#include "../include/DNS_util.h"

#include <inttypes.h>
#include <stdlib.h>

extern inline void ui8_ptr_stack_init(ui8_ptr_stack_t* s) { s->top = -1; }

extern inline int ui8_ptr_stack_push(ui8_ptr_stack_t* s, uint8_t* ptr) {
    if (s->top >= MAX_DNS_JUMP - 1)
        return -1;
    s->data[++(s->top)] = ptr;
    return 0;
}

extern inline uint8_t* ui8_ptr_stack_pop(ui8_ptr_stack_t* s) {
    if (s->top < 0)
        return NULL;
    return s->data[(s->top)--];
}