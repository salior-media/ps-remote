/* Minimal shim of chiaki-ng's headers, enough to compile rpcrypt.c's table code. */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <assert.h>
#define CHIAKI_EXPORT
#define CHIAKI_RPCRYPT_KEY_SIZE 0x10
typedef enum { CHIAKI_ERR_SUCCESS = 0, CHIAKI_ERR_UNKNOWN, CHIAKI_ERR_INVALID_DATA } ChiakiErrorCode;
typedef enum { CHIAKI_TARGET_PS4_UNKNOWN = 0, CHIAKI_TARGET_PS4_8 = 800, CHIAKI_TARGET_PS4_9 = 900,
  CHIAKI_TARGET_PS4_10 = 1000, CHIAKI_TARGET_PS5_UNKNOWN = 1000000, CHIAKI_TARGET_PS5_1 = 1000100 } ChiakiTarget;
static inline bool chiaki_target_is_ps5(ChiakiTarget t) { return t >= CHIAKI_TARGET_PS5_UNKNOWN; }
typedef struct { ChiakiTarget target; uint8_t bright[16]; uint8_t ambassador[16]; } ChiakiRPCrypt;
