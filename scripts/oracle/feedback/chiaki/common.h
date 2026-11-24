// Minimal stand-in for chiaki-ng's lib/include/chiaki/common.h: only what feedback.c and controller.c use.
#ifndef CHIAKI_COMMON_H
#define CHIAKI_COMMON_H
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#define CHIAKI_EXPORT
typedef enum { CHIAKI_ERR_SUCCESS = 0, CHIAKI_ERR_BUF_TOO_SMALL = 2, CHIAKI_ERR_MEMORY = 3, CHIAKI_ERR_INVALID_DATA = 10 } ChiakiErrorCode;
typedef uint16_t chiaki_unaligned_uint16_t __attribute__((aligned(1)));
#endif
