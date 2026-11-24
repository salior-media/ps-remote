/* RFC 4648 base64, standing in for chiaki-ng's OpenSSL-backed chiaki_base64_encode. */
static inline ChiakiErrorCode chiaki_base64_encode(const uint8_t *in, size_t in_size, char *out, size_t out_size) {
	static const char t[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	size_t o = 0;
	for(size_t i = 0; i < in_size; i += 3) {
		uint32_t v = in[i] << 16 | (i + 1 < in_size ? in[i+1] << 8 : 0) | (i + 2 < in_size ? in[i+2] : 0);
		out[o++] = t[v >> 18 & 63]; out[o++] = t[v >> 12 & 63];
		out[o++] = i + 1 < in_size ? t[v >> 6 & 63] : '=';
		out[o++] = i + 2 < in_size ? t[v & 63] : '=';
	}
	out[o] = 0; (void)out_size; return CHIAKI_ERR_SUCCESS;
}
