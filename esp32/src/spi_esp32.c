/* SPDX-License-Identifier: Apache-2.0 */
/*
 * spi_esp32.c - ESP32 has no Linux spidev; the reader talks to the PN7160 over
 * I2C (Wire, i2c_esp32). This stub satisfies transport.c's nci_spi_* references
 * so the I2C build links - the SPI branch (bus_type == NCI_BUS_SPI) is never
 * taken on this platform. Port to the Arduino SPI library to enable SPI on-chip.
 */
#include "spi.h"

nci_spi *nci_spi_open(const char *dev, uint32_t speed_hz, uint8_t mode)
{
    (void)dev; (void)speed_hz; (void)mode;
    return 0;   /* NULL: SPI byte-pipe unavailable on this platform */
}

void nci_spi_close(nci_spi *s) { (void)s; }

int nci_spi_write(nci_spi *s, const uint8_t *buf, size_t len)
{
    (void)s; (void)buf; (void)len;
    return -1;
}

int nci_spi_read(nci_spi *s, uint8_t *buf, size_t len)
{
    (void)s; (void)buf; (void)len;
    return -1;
}
