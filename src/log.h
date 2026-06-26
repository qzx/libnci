/* SPDX-License-Identifier: Apache-2.0 */
/*
 * log.h - Minimal logging. Quiet by default; set PN7160_DEBUG=1 in the
 * environment to see debug/trace output. Errors always go to stderr.
 */
#ifndef PN7160_LOG_H
#define PN7160_LOG_H

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>

static inline int pn7160_debug_enabled(void)
{
    static int cached = -1;
    if (cached < 0) {
        const char *v = getenv("PN7160_DEBUG");
        cached = (v && *v && *v != '0') ? 1 : 0;
    }
    return cached;
}

#define LOGE(...) do { fprintf(stderr, "[pn7160][E] " __VA_ARGS__); \
                       fprintf(stderr, "\n"); } while (0)

#define LOGD(...) do { if (pn7160_debug_enabled()) { \
                          fprintf(stderr, "[pn7160][D] " __VA_ARGS__); \
                          fprintf(stderr, "\n"); } } while (0)

/* Hex-dump a buffer at debug level with a leading tag. */
static inline void pn7160_log_hex(const char *tag, const uint8_t *buf, size_t len)
{
    if (!pn7160_debug_enabled()) return;
    fprintf(stderr, "[pn7160][D] %s (%zu):", tag, len);
    for (size_t i = 0; i < len; i++)
        fprintf(stderr, " %02x", buf[i]);
    fprintf(stderr, "\n");
}

#endif /* PN7160_LOG_H */
