/* SPDX-License-Identifier: Apache-2.0 */
/*
 * log.h - Leveled diagnostics (impl.txt #129). Silent by default except errors.
 *
 * Levels (low -> high verbosity), selectable at runtime with no external dep:
 *   0 SILENT  nothing at all
 *   1 ERROR   errors only                    (default)
 *   2 WARN    + recoverable/abnormal events
 *   3 INFO    + high-level operations (LOGD)
 *   4 NCI     + NCI control frames (SEND/RECV hex)
 *   5 BYTES   + raw I2C/SPI byte traffic
 *
 * Set via hci_set_log_level() (public API) or the environment, resolved once:
 *   NCI_LOG=<0..5>            explicit level
 *   NCI_DEBUG / PN7160_DEBUG  legacy boolean -> NCI level (frames)
 */
#ifndef PN7160_LOG_H
#define PN7160_LOG_H

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>

enum {
    PN7160_LOG_SILENT = 0,
    PN7160_LOG_ERROR  = 1,
    PN7160_LOG_WARN   = 2,
    PN7160_LOG_INFO   = 3,
    PN7160_LOG_NCI    = 4,
    PN7160_LOG_BYTES  = 5,
};

/* Current level (resolves the environment on first call). */
int  pn7160_log_level(void);
/* Override the level programmatically (clamped to 0..5). */
void pn7160_log_set_level(int level);
/* Hex-dump a buffer, but only if the current level >= `level`. */
void pn7160_log_hex_at(int level, const char *tag, const uint8_t *buf, size_t len);

#define LOGE(...) do { if (pn7160_log_level() >= PN7160_LOG_ERROR) { \
                          fprintf(stderr, "[nci][E] " __VA_ARGS__); fprintf(stderr, "\n"); } } while (0)
#define LOGW(...) do { if (pn7160_log_level() >= PN7160_LOG_WARN) { \
                          fprintf(stderr, "[nci][W] " __VA_ARGS__); fprintf(stderr, "\n"); } } while (0)
#define LOGD(...) do { if (pn7160_log_level() >= PN7160_LOG_INFO) { \
                          fprintf(stderr, "[nci][D] " __VA_ARGS__); fprintf(stderr, "\n"); } } while (0)

/* Back-compat: the NCI-frame hex dumper (transport SEND/RECV/DRAIN). */
static inline void pn7160_log_hex(const char *tag, const uint8_t *buf, size_t len)
{
    pn7160_log_hex_at(PN7160_LOG_NCI, tag, buf, len);
}

#endif /* PN7160_LOG_H */
