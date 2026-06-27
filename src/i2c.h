/* SPDX-License-Identifier: Apache-2.0 */
/*
 * i2c.h - Layer 1: a raw I2C byte pipe to the NFCC.
 *
 * No NCI knowledge here - it just opens /dev/i2c-N, selects the slave
 * address, and does read()/write(). Packet framing lives one layer up.
 */
#ifndef NCI_I2C_H
#define NCI_I2C_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct nci_i2c nci_i2c;   /* opaque */

nci_i2c *nci_i2c_open(const char *bus, uint16_t addr);
void        nci_i2c_close(nci_i2c *i);

/* One I2C transaction each. Return bytes transferred, or <0 on error. */
int nci_i2c_write(nci_i2c *i, const uint8_t *buf, size_t len);
int nci_i2c_read (nci_i2c *i, uint8_t *buf, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* NCI_I2C_H */
