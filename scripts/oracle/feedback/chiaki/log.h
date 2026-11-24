// Minimal stand-in for chiaki-ng's lib/include/chiaki/log.h: logging is dropped.
#ifndef CHIAKI_LOG_H
#define CHIAKI_LOG_H
typedef struct chiaki_log_t ChiakiLog;
#define CHIAKI_LOGE(log, ...) ((void)(log))
#endif
