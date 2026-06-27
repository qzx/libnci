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

/* read() returns this when interrupted by abort() from another thread. */
#define PN7160_TRANSPORT_ABORTED (-2)

typedef struct {
    void *ctx;
    /* Write a complete NCI packet. Returns bytes written or <0. */
    int (*write)(void *ctx, const uint8_t *buf, size_t len);
    /* Read exactly one complete NCI packet (3-byte header + payload),
     * blocking on IRQ up to timeout_ms (<0 = forever).
     * Returns total bytes, 0 on timeout, PN7160_TRANSPORT_ABORTED on abort,
     * <0 on error. */
    int (*read)(void *ctx, uint8_t *buf, size_t cap, int timeout_ms);
    /* Drive the VEN/DWL reset choreography. fw_download selects boot mode. */
    int (*reset)(void *ctx, bool fw_download);
    /* Interrupt a blocked read() from another thread (may be NULL). */
    void (*abort)(void *ctx);
    /* Status byte of the most recent NCI command response (impl.txt #128).
     * The NCI layer records it on every RSP; 0x00 = STATUS_OK. */
    uint8_t last_nci_status;
} pn7160_transport;

/* Build the concrete I2C + libgpiod transport from config. */
pn7160_transport *pn7160_transport_open(const pn7160_config *cfg);
void              pn7160_transport_close(pn7160_transport *t);

#ifdef __cplusplus
}
#endif

#endif /* PN7160_TRANSPORT_H */
