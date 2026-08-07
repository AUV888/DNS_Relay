#include <stdio.h>

#include "../include/DNS_debug.h"

void read_data(log_event_t l, uint16_t thread_id) {
    /* Writer tag first, so every moredebug line shows which thread
     * emitted the event. */
    if (thread_id == LOG_THREAD_ID_MAIN)
        printf("[main] ");
    else
        printf("[pth%u] ", (unsigned)thread_id);

    switch (l) {
        case LOCAL_SOCKET_FAILED: {
            printf("LOCAL_SOCKET_FAILED\n");
            break;
        }
        case REMOTE_SOCKET_FAILED: {
            printf("REMOTE_SOCKET_FAILED\n");
            break;
        }
        case SOCKET_OPT_FAILED: {
            printf("SOCKET_OPT_FAILED\n");
            break;
        }
        case SOCKET_BIND_FAILED: {
            printf("SOCKET_BIND_FAILED\n");
            break;
        }
        case SOCKET_INIT_SUCCESS: {
            printf("SOCKET_INIT_SUCCESS\n");
            break;
        }
        case SOCKET_CLOSE_SUCCESS: {
            printf("SOCKET_CLOSE_SUCCESS\n");
            break;
        }
        case LOCAL_RECEIVE_RECVFROM_FAILED: {
            printf("LOCAL_RECEIVE_RECVFROM_FAILED\n");
            break;
        }
        case LOCAL_RECEIVE_DECODE_NULL_HEADER: {
            printf("LOCAL_RECEIVE_DECODE_NULL_HEADER\n");
            break;
        }
        case LOCAL_RECEIVE_CAN_RESOLVE_LOCALLY: {
            printf("LOCAL_RECEIVE_CAN_RESOLVE_LOCALLY\n");
            break;
        }
        case LOCAL_RECEIVE_HIT_CACHE: {
            printf("LOCAL_RECEIVE_HIT_CACHE\n");
            break;
        }
        case LOCAL_RECEIVE_ANS_MALLOC_FAILED: {
            printf("LOCAL_RECEIVE_ANS_MALLOC_FAILED\n");
            break;
        }
        case LOCAL_RECEIVE_ANS_NAME_MALLOC_FAILED: {
            printf("LOCAL_RECEIVE_ANS_NAME_MALLOC_FAILED\n");
            break;
        }
        case LOCAL_RECEIVE_REPLY_SIZE_ERROR: {
            printf("LOCAL_RECEIVE_REPLY_SIZE_ERROR\n");
            break;
        }
        case LOCAL_RECEIVE_DNS_MESSAGE_FREE_SUCCESS: {
            printf("LOCAL_RECEIVE_DNS_MESSAGE_FREE_SUCCESS\n");
            break;
        }
        case LOCAL_RECEIVE_CANNOT_HIT_CACHE: {
            printf("LOCAL_RECEIVE_CANNOT_HIT_CACHE\n");
            break;
        }
        case LOCAL_RECEIVE_NO_EMPTY_SLOT_DROP: {
            printf("LOCAL_RECEIVE_NO_EMPTY_SLOT_DROP\n");
            break;
        }
        case LOCAL_RECEIVE_SENT_TO_UPSTREAM: {
            printf("LOCAL_RECEIVE_SENT_TO_UPSTREAM\n");
            break;
        }
        case REMOTE_RECEIVE_MSG_SIZE_ERR: {
            printf("REMOTE_RECEIVE_MSG_SIZE_ERR\n");
            break;
        }
        case REMOTE_RECEIVE_NO_ORIG_ID_DROP: {
            printf("REMOTE_RECEIVE_NO_ORIG_ID_DROP\n");
            break;
        }
        case REMOTE_RECEIVE_SENT_TO_CLIENT: {
            printf("REMOTE_RECEIVE_SENT_TO_CLIENT\n");
            break;
        }
        case REMOTE_RECEIVE_NO_GLOBAL_CACHE: {
            printf("REMOTE_RECEIVE_NO_GLOBAL_CACHE\n");
            break;
        }
        case REMOTE_RECEIVE_HAS_GLOBAL_CACHE: {
            printf("REMOTE_RECEIVE_HAS_GLOBAL_CACHE\n");
            break;
        }
        case REMOTE_RECEIVE_CACHED_ANSWER_SUCCESS: {
            printf("REMOTE_RECEIVE_CACHED_ANSWER_SUCCESS\n");
            break;
        }
        case BLOCK_MODE_START: {
            printf("BLOCK_MODE_START\n");
            break;
        }
        case BLOCK_MODE_ERRNO_EINTR: {
            printf("BLOCK_MODE_ERRNO_EINTR\n");
            break;
        }
        case BLOCK_MODE_TIMEOUT: {
            printf("BLOCK_MODE_TIMEOUT\n");
            break;
        }
        case BLOCK_MODE_LOCAL_RECEIVE: {
            printf("BLOCK_MODE_LOCAL_RECEIVE\n");
            break;
        }
        case BLOCK_MODE_REMOTE_RECEIVE: {
            printf("BLOCK_MODE_REMOTE_RECEIVE\n");
            break;
        }
        case NON_BLOCK_MODE_START: {
            printf("NON_BLOCK_MODE_START\n");
            break;
        }
        case NON_BLOCK_MODE_LOCAL_FGETFL_ERR: {
            printf("NON_BLOCK_MODE_LOCAL_FGETFL_ERR\n");
            break;
        }
        case NON_BLOCK_MODE_LOCAL_FSETFL_ERR: {
            printf("NON_BLOCK_MODE_LOCAL_FSETFL_ERR\n");
            break;
        }
        case NON_BLOCK_MODE_REMOTE_FGETFL_ERR: {
            printf("NON_BLOCK_MODE_REMOTE_FGETFL_ERR\n");
            break;
        }
        case NON_BLOCK_MODE_REMOTE_FSETFL_ERR: {
            printf("NON_BLOCK_MODE_REMOTE_FSETFL_ERR\n");
            break;
        }
        case NON_BLOCK_SWEEP: {
            printf("NON_BLOCK_SWEEP\n");
            break;
        }
        case CACHE_FIND: {
            printf("CACHE_FIND\n");
            break;
        }
        case CACHE_CLEAR: {
            printf("CACHE_CLEAR\n");
            break;
        }
        case CACHE_ERASE: {
            printf("CACHE_ERASE\n");
            break;
        }
        case CACHE_INSERT: {
            printf("CACHE_INSERT\n");
            break;
        }
        case CACHE_DESTROY: {
            printf("CACHE_DESTROY\n");
            break;
        }
        case CACHE_INIT: {
            printf("CACHE_INIT\n");
            break;
        }
        case CREATE_HSET_ERR: {
            printf("CREATE_HSET_ERR\n");
            break;
        }
        case CREATE_HSET_SUCCESS: {
            printf("CREATE_HSET_SUCCESS\n");
            break;
        }
        case CONVERT_READ_BYTE_ERR: {
            printf("CONVERT_READ_BYTE_ERR\n");
            break;
        }
        case CONVERT_WRITE_BYTE: {
            printf("CONVERT_WRITE_BYTE\n");
            break;
        }
        case GET_DNS_HEADER_SUCCESS: {
            printf("GET_DNS_HEADER_SUCCESS\n");
            break;
        }
        case GET_DNS_QUESTION_MALLOC_ERR: {
            printf("GET_DNS_QUESTION_MALLOC_ERR\n");
            break;
        }
        case GET_DNS_QUESTION_SUCCESS: {
            printf("GET_DNS_QUESTION_SUCCESS\n");
            break;
        }
        case GET_DNS_DOMAIN_SUCCESS: {
            printf("GET_DNS_DOMAIN_SUCCESS\n");
            break;
        }
        case GET_DNS_ANSWER_NULL_PTR_ERR: {
            printf("GET_DNS_ANSWER_NULL_PTR_ERR\n");
            break;
        }
        case GET_DNS_ANSWER_NOT_SUPPORTED_TYPE_ERR: {
            printf("GET_DNS_ANSWER_NOT_SUPPORTED_TYPE_ERR\n");
            break;
        }
        case DNS_MESSAGE_DECODE_SUCCESS: {
            printf("DNS_MESSAGE_DECODE_SUCCESS\n");
            break;
        }
        case SET_DNS_HEADER_SUCCESS: {
            printf("SET_DNS_HEADER_SUCCESS\n");
            break;
        }
        case SET_DNS_DOMAIN_SUCCESS: {
            printf("SET_DNS_DOMAIN_SUCCESS\n");
            break;
        }
        case SET_DNS_QUESTION_SUCCESS: {
            printf("SET_DNS_QUESTION_SUCCESS\n");
            break;
        }
        case SET_DNS_ANSWER_SUCCESS: {
            printf("SET_DNS_ANSWER_SUCCESS\n");
            break;
        }
        case DNS_MESSAGE_ENCODE_SUCCESS: {
            printf("DNS_MESSAGE_ENCODE_SUCCESS\n");
            break;
        }
        case DNS_MESSAGE_FREE_SUCCESS: {
            printf("DNS_MESSAGE_FREE_SUCCESS\n");
            break;
        }
        case ID_MAP_INIT: {
            printf("ID_MAP_INIT\n");
            break;
        }
        case ID_MAP_INSERT_ARGS_NULL_PTR_ERR: {
            printf("ID_MAP_INSERT_ARGS_NULL_PTR_ERR\n");
            break;
        }
        case ID_MAP_INSERT_FULL_TABLE_ERR: {
            printf("ID_MAP_INSERT_FULL_TABLE_ERR\n");
            break;
        }
        case ID_MAP_FIND_ID_OUT_BOUND_ERR: {
            printf("ID_MAP_FIND_ID_OUT_BOUND_ERR\n");
            break;
        }
        case ID_MAP_FIND_USED_ID_ERR: {
            printf("ID_MAP_FIND_USED_ID_ERR\n");
            break;
        }
        case ID_MAP_FIND_TIMEOUT_ERR: {
            printf("ID_MAP_FIND_TIMEOUT_ERR\n");
            break;
        }
        case ID_MAP_FIND_SUCCESS: {
            printf("ID_MAP_FIND_SUCCESS\n");
            break;
        }
        case ID_MAP_ERASE_ID_OUT_BOUND_ERR: {
            printf("ID_MAP_ERASE_ID_OUT_BOUND_ERR\n");
            break;
        }
        case ID_MAP_ERASE_ID_MAP_USED_ERR: {
            printf("ID_MAP_ERASE_ID_MAP_USED_ERR\n");
            break;
        }
        case ID_MAP_ERASED_SUCCESS: {
            printf("ID_MAP_ERASED_SUCCESS\n");
            break;
        }
        case ID_MAP_SWEEP_TIMEOUT_SUCCESS: {
            printf("ID_MAP_SWEEP_TIMEOUT_SUCCESS\n");
            break;
        }
        case UI8_PTR_STACK_INIT: {
            printf("UI8_PTR_STACK_INIT\n");
            break;
        }
        case UI8_PTR_STACK_PUSH: {
            printf("UI8_PTR_STACK_PUSH\n");
            break;
        }
        case UI8_PTR_STACK_POP: {
            printf("UI8_PTR_STACK_POP\n");
            break;
        }
        case BLOCK_MODE_ERRNO_SELECT: {
            printf("BLOCK_MODE_ERRNO_SELECT\n");
            break;
        }
        case NON_BLOCK_MODE_LOCAL_RECEIVE: {
            printf("NON_BLOCK_MODE_LOCAL_RECEIVE\n");
            break;
        }
        case NON_BLOCK_MODE_REMOTE_RECEIVE: {
            printf("NON_BLOCK_MODE_REMOTE_RECEIVE\n");
            break;
        }
        case CACHE_FIND_SRC: {
            printf("CACHE_FIND_SRC\n");
            break;
        }
        case CACHE_FIND_HASH: {
            printf("CACHE_FIND_HASH\n");
            break;
        }
        case GET_DNS_ANSWER_SUCCESS: {
            printf("GET_DNS_ANSWER_SUCCESS\n");
            break;
        }
        default:
            break;
    }
}