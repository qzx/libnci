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
 * Set via nci_set_log_level() (public API) or the environment, resolved once:
 *   NCI_LOG=<0..5>            explicit level
 *   NCI_DEBUG / PN7160_DEBUG  legacy boolean -> NCI level (frames)
 */
#ifndef NCI_LOG_H
#define NCI_LOG_H

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>

enum {
    NCI_LVL_SILENT = 0,
    NCI_LVL_ERROR  = 1,
    NCI_LVL_WARN   = 2,
    NCI_LVL_INFO   = 3,
    NCI_LVL_NCI    = 4,
    NCI_LVL_BYTES  = 5,
};

/* Current level (resolves the environment on first call). */
int  nci_log_get_level(void);
/* Override the level programmatically (clamped to 0..5). */
void nci_log_set_level(int level);
/* Hex-dump a buffer, but only if the current level >= `level`. */
void nci_log_hex_at(int level, const char *tag, const uint8_t *buf, size_t len);

#define LOGE(...) do { if (nci_log_get_level() >= NCI_LVL_ERROR) { \
                          fprintf(stderr, "[nci][E] " __VA_ARGS__); fprintf(stderr, "\n"); } } while (0)
#define LOGW(...) do { if (nci_log_get_level() >= NCI_LVL_WARN) { \
                          fprintf(stderr, "[nci][W] " __VA_ARGS__); fprintf(stderr, "\n"); } } while (0)
#define LOGD(...) do { if (nci_log_get_level() >= NCI_LVL_INFO) { \
                          fprintf(stderr, "[nci][D] " __VA_ARGS__); fprintf(stderr, "\n"); } } while (0)

/* Back-compat: the NCI-frame hex dumper (transport SEND/RECV/DRAIN). */
static inline void nci_log_hex(const char *tag, const uint8_t *buf, size_t len)
{
    nci_log_hex_at(NCI_LVL_NCI, tag, buf, len);
}

#endif /* NCI_LOG_H */
