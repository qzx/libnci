/* SPDX-License-Identifier: Apache-2.0 */
/*
 * spi.h - Layer 1: a raw SPI byte pipe to the NFCC (spidev).
 *
 * The sibling of i2c.h. No NCI knowledge here - it just opens /dev/spidevA.B,
 * sets mode/speed/bits, and does full-duplex read()/write() transfers. Packet
 * framing (the 3-byte NCI header + payload) lives one layer up in transport.c,
 * unchanged from the I2C path: "same transport.c framing, different byte-pipe"
 * (impl.txt #117).
 *
 * The PN7160 is the SPI-capable part in this tree; the PN7150 is I2C-only.
 */
#ifndef NCI_SPI_H
#define NCI_SPI_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct nci_spi nci_spi;   /* opaque */

/* Open a spidev node (e.g. "/dev/spidev0.0").
 *   speed_hz : SPI clock; 0 => a conservative default (NCI_SPI_DEFAULT_HZ).
 *   mode     : SPI CPOL/CPHA (SPI_MODE_0..3). The PN7160 uses mode 0.
 * Returns NULL on failure. */
nci_spi *nci_spi_open(const char *dev, uint32_t speed_hz, uint8_t mode);
void        nci_spi_close(nci_spi *s);

/* One SPI transfer each, mirroring the i2c.c read/write shape.
 *   write : clocks out `buf` (MOSI), MISO discarded.
 *   read  : clocks `len` dummy bytes out, capturing MISO into `buf`.
 * Return bytes transferred, or <0 on error. */
int nci_spi_write(nci_spi *s, const uint8_t *buf, size_t len);
int nci_spi_read (nci_spi *s, uint8_t *buf, size_t len);

/* Used when cfg->spi_speed_hz is left 0. 1 MHz is safe for every PN7160 wiring;
 * production can raise it via nci_config.spi_speed_hz. */
#define NCI_SPI_DEFAULT_HZ 1000000u

#ifdef __cplusplus
}
#endif

#endif /* NCI_SPI_H */
