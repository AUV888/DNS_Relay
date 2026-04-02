#ifndef DNS_UTIL_H
#define DNS_UTIL_H
#define MAX_DNS_JUMP 16
#include <inttypes.h>

struct ui8_ptr_stack {
    uint8_t* data[MAX_DNS_JUMP];
    int top;
};
typedef struct ui8_ptr_stack ui8_ptr_stack_t;

void ui8_ptr_stack_init(ui8_ptr_stack_t* s);

int ui8_ptr_stack_push(ui8_ptr_stack_t* s, uint8_t* ptr);

uint8_t* ui8_ptr_stack_pop(ui8_ptr_stack_t* s);
#endif