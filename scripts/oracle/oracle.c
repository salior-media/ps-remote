#include "chiaki/rpcrypt.h"
#include <stdio.h>
#include "rpcrypt_part.c"
static void hex(const char *k, const uint8_t *b) { printf("%s=", k); for (int i = 0; i < 16; i++) printf("%02x", b[i]); printf(" "); }
int main(void) {
  ChiakiTarget targets[] = { CHIAKI_TARGET_PS4_10, CHIAKI_TARGET_PS5_1 };
  for (int t = 0; t < 2; t++) for (int c = 0; c < 4; c++) {
    uint8_t nonce[16], morning[16], bright[16], amb[16], aero[16], aeropsn[16], back[16];
    for (int i = 0; i < 16; i++) { nonce[i] = (uint8_t)(c * 61 + i * 17 + 3); morning[i] = (uint8_t)(c * 29 + i * 11 + 200); }
    bright_ambassador(targets[t], bright, amb, nonce, morning);
    size_t off = (size_t)(c * 9) % 0x20;
    chiaki_rpcrypt_aeropause(targets[t], off, aero, amb);
    chiaki_rpcrypt_aeropause_psn(targets[t], off, aeropsn, amb);
    chiaki_rpcrypt_ambassador_from_aeropause(targets[t], off, aeropsn, back);
    ChiakiRPCrypt r; chiaki_rpcrypt_init_regist(&r, targets[t], amb, off, 12345678u + c);
    printf("target=%d case=%d off=%zu ", targets[t], c, off);
    hex("nonce", nonce); hex("morning", morning); hex("bright", bright); hex("ambassador", amb);
    hex("aeropause", aero); hex("aeropause_psn", aeropsn); hex("regist_bright", r.bright);
    printf("roundtrip=%s\n", memcmp(back, amb, 16) == 0 ? "ok" : "BAD");
  }
  return 0;
}
