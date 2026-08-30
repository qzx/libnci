/* SPDX-License-Identifier: Apache-2.0 */
/*
 * transport.h - Layer 2: NCI packet framing over a byte bus + reset control.
 *
 * The NCI layer (layer 3) depends only on the nci_transport vtable below.
 * It has no idea whether bytes go over I2C, SPI, or a unit-test mock - which
 * is exactly what makes the NCI logic testable without hardware.
 *
 * See doc/NCI_libgpiod2_library_design.md §5.1.
 */
#ifndef NCI_TRANSPORT_H
#define NCI_TRANSPORT_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "nci/config.h"

#ifdef __cplusplus
extern "C" {
#endif

/* read() returns this when interrupted by abort() from another thread. */
#define NCI_TRANSPORT_ABORTED (-2)

typedef struct {
    void *ctx;
    /* Write a complete NCI packet. Returns bytes written or <0. */
    int (*write)(void *ctx, const uint8_t *buf, size_t len);
    /* Read exactly one complete NCI packet (3-byte header + payload),
     * blocking on IRQ up to timeout_ms (<0 = forever).
     * Returns total bytes, 0 on timeout, NCI_TRANSPORT_ABORTED on abort,
     * <0 on error. */
    int (*read)(void *ctx, uint8_t *buf, size_t cap, int timeout_ms);
    /* Drive the VEN/DWL reset choreography. fw_download selects boot mode. */
    int (*reset)(void *ctx, bool fw_download);
    /* Interrupt a blocked read() from another thread (may be NULL). */
    void (*abort)(void *ctx);
    /* Status byte of the most recent NCI command response (impl.txt #128).
     * The NCI layer records it on every RSP; 0x00 = STATUS_OK. */
    uint8_t last_nci_status;
} nci_transport;

/* Build the concrete I2C-or-SPI + libgpiod transport from config. The byte-pipe
 * is chosen from cfg->bus_type (NCI_BUS_I2C / NCI_BUS_SPI); framing is identical. */
nci_transport *nci_transport_open(const nci_config *cfg);
void              nci_transport_close(nci_transport *t);

/* Open an nci device over a caller-supplied transport instead of a built-in bus.
 * Standard NCI bring-up (CORE_RESET/INIT, RF_DISCOVER_MAP), no chipset configure
 * hook, so the whole public nci_* device API drives over `t`. Available in EVERY
 * build (hardware or headless): the test seam for exercising the device layer
 * against a mock transport, and the entry point for a custom byte pipe. Ownership
 * of `t` transfers to the returned handle. NULL on any bring-up failure. */
struct nci;
struct nci *nci_open_transport(nci_transport *t);

/* ---- PN7160/PN71xx firmware download (DWL) ----------------------------- *
 * Entry points for the NXP firmware-download protocol (impl.txt #118), which
 * makes NCI_CAP_FW_UPDATE real beyond the DWL-pin reset choreography. In DWL
 * mode the controller does NOT speak NCI: frames use the NXP download format
 *
 *     [LEN_HI LEN_LO] [CMD] [DATA...] [CRC16_HI CRC16_LO]
 *
 * where LEN counts CMD+DATA+CRC and CRC16 is CRC-16-CCITT over LEN+CMD+DATA.
 * These functions bypass the NCI header framing and talk the raw byte-pipe.
 *
 * STUBBED / UNVERIFIED (no PN7160 + no NXP firmware blob on the bench here):
 * the exact DWL command opcodes and the CRC seed are transcribed from the NXP
 * download protocol and MUST be confirmed against UM11495 before flashing real
 * silicon; the full image sectioning/flasher (parse .so/.bin, chunk, verify) is
 * NOT implemented - only the session entry points and frame codec are. */

/* Boot the controller into DWL mode (DWL_REQ high across a VEN reset). */
int nci_dwl_enter(nci_transport *t);

/* Leave DWL mode: send the download RESET frame, then a normal boot. */
int nci_dwl_leave(nci_transport *t);

/* GetVersion in DWL mode: sends the GETVERSION frame and returns the response
 * DATA (after the status byte) in out, with *out_len set. NCI_OK or negative. */
int nci_dwl_get_version(nci_transport *t, uint8_t *out, size_t cap, size_t *out_len);

/* Push one firmware WRITE frame (a single chunk of an already-sectioned image).
 * The image parser that produces these chunks is out of scope (see above). */
int nci_dwl_write_chunk(nci_transport *t, const uint8_t *chunk, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* NCI_TRANSPORT_H */
