/* SPDX-License-Identifier: Apache-2.0 */
/*
 * i2c_esp32.cpp - ESP32 I2C byte pipe for libnci (replaces src/i2c.c).
 *
 * Implements the i2c.h interface over the Arduino `Wire` library. The sketch
 * must select the SDA/SCL pins with Wire.begin(SDA, SCL) before nci_open();
 * this file only does the per-transaction read/write to the NFCC's address.
 *
 * NCI packets reach 3 + 255 = 258 bytes, larger than Wire's default 128-byte
 * buffer, so we enlarge it. transport.c handles the half-duplex write retry;
 * the read here mirrors the Linux backend's bounded EREMOTEIO retry.
 *
 * i2c.h declares these with C linkage (extern "C"), so the definitions below
 * inherit C linkage and link against the C transport layer.
 */
#include <Arduino.h>
#include <Wire.h>
#include <stdlib.h>
#include "i2c.h"

#define NCI_I2C_BUFSZ 320   /* >= max NCI packet (258) with headroom */

struct nci_i2c { uint16_t addr; };

nci_i2c *nci_i2c_open(const char *bus, uint16_t addr)
{
    (void)bus;                        /* pins are chosen by the sketch's Wire.begin */
    nci_i2c *i = (nci_i2c *)malloc(sizeof(nci_i2c));
    if (!i) return NULL;
    i->addr = addr;
    Wire.setBufferSize(NCI_I2C_BUFSZ);  /* belt-and-suspenders; sketch should also do this before Wire.begin */
    return i;
}

void nci_i2c_close(nci_i2c *i)
{
    if (i) free(i);
}

/* One I2C write transaction. transport.c retries on failure, so a single
 * attempt here is correct. Returns bytes written, or <0. */
int nci_i2c_write(nci_i2c *i, const uint8_t *buf, size_t len)
{
    if (!i || !buf) return -1;
    Wire.beginTransmission((uint8_t)i->addr);
    size_t w = Wire.write(buf, len);
    if (Wire.endTransmission(true) != 0) return -1;   /* NAK / bus error */
    return (w == len) ? (int)len : -1;
}

/* One I2C read transaction with a short bounded retry (the PN7160 transiently
 * NAKs a read issued a touch early - same fix as the Linux EREMOTEIO retry). */
int nci_i2c_read(nci_i2c *i, uint8_t *buf, size_t len)
{
    if (!i || !buf || len == 0) return -1;
    for (int attempt = 0; attempt < 8; attempt++) {
        size_t got = Wire.requestFrom((uint16_t)i->addr, (size_t)len, (bool)true);
        if (got == len) {
            for (size_t k = 0; k < len; k++) buf[k] = (uint8_t)Wire.read();
            return (int)len;
        }
        while (Wire.available()) Wire.read();   /* drop a partial read */
        delay(1);
    }
    return -1;
}
