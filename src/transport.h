/* SPDX-License-Identifier: Apache-2.0 */
/*
 * transport.h - Layer 2: NCI packet framing over a byte bus + reset control.
 *
 * The NCI layer (layer 3) depends only on the pn7160_transport vtable below.
 * It has no idea whether bytes go over I2C, SPI, or a unit-test mock - which
 * is exactly what makes the NCI logic testable without hardware.
 *
 * See doc/PN7160_libgpiod2_library_design.md §5.1.
 */
#ifndef PN7160_TRANSPORT_H
#define PN7160_TRANSPORT_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "pn7160/pn7160_config.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    void *ctx;
    /* Write a complete NCI packet. Returns bytes written or <0. */
    int (*write)(void *ctx, const uint8_t *buf, size_t len);
    /* Read exactly one complete NCI packet (3-byte header + payload),
     * blocking on IRQ up to timeout_ms (<0 = forever).
     * Returns total bytes, 0 on timeout, <0 on error. */
    int (*read)(void *ctx, uint8_t *buf, size_t cap, int timeout_ms);
    /* Drive the VEN/DWL reset choreography. fw_download selects boot mode. */
    int (*reset)(void *ctx, bool fw_download);
} pn7160_transport;

/* Build the concrete I2C + libgpiod transport from config. */
pn7160_transport *pn7160_transport_open(const pn7160_config *cfg);
void              pn7160_transport_close(pn7160_transport *t);

#ifdef __cplusplus
}
#endif

#endif /* PN7160_TRANSPORT_H */
