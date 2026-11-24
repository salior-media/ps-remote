/* Minimal shim of chiaki-ng's headers, enough to compile lib/src/launchspec.c. */
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
typedef enum { CHIAKI_TARGET_PS4_10 = 1000, CHIAKI_TARGET_PS5_1 = 1000100 } ChiakiTarget;
typedef enum { CHIAKI_CODEC_H264 = 0, CHIAKI_CODEC_H265 = 1, CHIAKI_CODEC_H265_HDR = 2 } ChiakiCodec;
typedef int ChiakiErrorCode;
#define CHIAKI_ERR_SUCCESS 0
#define CHIAKI_EXPORT
#define CHIAKI_HANDSHAKE_KEY_SIZE 0x10
static inline bool chiaki_target_is_ps5(ChiakiTarget t) { return t >= 1000000; }
static inline bool chiaki_codec_is_h265(ChiakiCodec c) { return c == CHIAKI_CODEC_H265 || c == CHIAKI_CODEC_H265_HDR; }
static inline bool chiaki_codec_is_hdr(ChiakiCodec c) { return c == CHIAKI_CODEC_H265_HDR; }
typedef struct { ChiakiTarget target; unsigned int width, height, max_fps; ChiakiCodec codec; unsigned int bw_kbps_sent, mtu, rtt; uint8_t *handshake_key; } ChiakiLaunchSpec;
int chiaki_launchspec_format(char *buf, size_t buf_size, ChiakiLaunchSpec *launch_spec);
