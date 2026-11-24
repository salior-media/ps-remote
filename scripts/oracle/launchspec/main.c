#include <stdio.h>
#include "chiaki/launchspec.h"
int main(void) {
	uint8_t key[16]; for(int i = 0; i < 16; i++) key[i] = (uint8_t)(i * 17 + 3);
	char buf[2048];
	ChiakiLaunchSpec s = { CHIAKI_TARGET_PS5_1, 1280, 720, 60, CHIAKI_CODEC_H264, 10000, 1454, 1, key };
	chiaki_launchspec_format(buf, sizeof(buf), &s); printf("ps5_h264 %s\n", buf);
	s.codec = CHIAKI_CODEC_H265_HDR; s.width = 1920; s.height = 1080; s.bw_kbps_sent = 15000;
	chiaki_launchspec_format(buf, sizeof(buf), &s); printf("ps5_hdr %s\n", buf);
	s.target = CHIAKI_TARGET_PS4_10; s.codec = CHIAKI_CODEC_H264;
	chiaki_launchspec_format(buf, sizeof(buf), &s); printf("ps4 %s\n", buf);
	return 0;
}
