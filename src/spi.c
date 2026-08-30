/* SPDX-License-Identifier: Apache-2.0 */
/*
 * spi.c - /dev/spidevA.B transport (Linux spidev), the SPI sibling of i2c.c.
 *
 * Mirrors i2c.c's open / read / write shape so transport.c can treat it as an
 * interchangeable byte-pipe (impl.txt #117: "same transport.c framing,
 * different byte-pipe"). The higher NCI 3-byte-header framing in transport.c is
 * unchanged; only the bytes travel over SPI instead of I2C.
 *
 * Transactions use SPI_IOC_MESSAGE full-duplex transfers:
 *   write  -> tx_buf = caller buffer, rx_buf = NULL (MISO ignored)
 *   read   -> tx_buf = NULL (spidev clocks out zeros), rx_buf = caller buffer
 * The controller's data-ready signalling stays on the IRQ GPIO, exactly as on
 * I2C - transport.c waits the IRQ edge, then issues the header read and the
 * payload read as two SPI transactions.
 *
 * UNVERIFIED (no PN7160 on the bench here): whether the PN7160 SPI slave needs a
 * per-transaction R/W control byte prefix (UM11495 "SPI interface") ahead of the
 * NCI bytes. If it does, that prefix belongs right here in the byte-pipe (so
 * transport.c stays bus-agnostic); the split-read header/payload handshake and
 * the exact SPI mode/CPHA must be confirmed against UM11495 on real silicon.
 */
#define _POSIX_C_SOURCE 200809L
#include "nci_spi.h"
#include "log.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/spi/spidev.h>

struct nci_spi {
    int      fd;
    uint32_t speed_hz;
    uint8_t  mode;
    uint8_t  bits;
};

nci_spi *nci_spi_open(const char *dev, uint32_t speed_hz, uint8_t mode)
{
    if (!dev) return NULL;
    nci_spi *s = calloc(1, sizeof *s);
    if (!s) return NULL;
    s->speed_hz = speed_hz ? speed_hz : NCI_SPI_DEFAULT_HZ;
    s->mode     = mode;
    s->bits     = 8;

    s->fd = open(dev, O_RDWR | O_NOCTTY);
    if (s->fd < 0) {
        LOGE("spi: open %s failed: %s (spidev loaded? in 'spi' group?)",
             dev, strerror(errno));
        free(s);
        return NULL;
    }
    if (ioctl(s->fd, SPI_IOC_WR_MODE, &s->mode) < 0) {
        LOGE("spi: set mode %u failed: %s", s->mode, strerror(errno));
        goto fail;
    }
    if (ioctl(s->fd, SPI_IOC_WR_BITS_PER_WORD, &s->bits) < 0) {
        LOGE("spi: set bits %u failed: %s", s->bits, strerror(errno));
        goto fail;
    }
    if (ioctl(s->fd, SPI_IOC_WR_MAX_SPEED_HZ, &s->speed_hz) < 0) {
        LOGE("spi: set speed %u Hz failed: %s", s->speed_hz, strerror(errno));
        goto fail;
    }
    LOGD("spi: %s open (fd %d) mode %u %u-bit %u Hz",
         dev, s->fd, s->mode, s->bits, s->speed_hz);
    return s;
fail:
    close(s->fd);
    free(s);
    return NULL;
}

void nci_spi_close(nci_spi *s)
{
    if (!s) return;
    if (s->fd >= 0) close(s->fd);
    free(s);
}

/* One full-duplex transfer. tx and/or rx may be NULL (spidev sends/ignores
 * zeros for a NULL side). Returns len on success, <0 on error. */
static int spi_xfer(nci_spi *s, const uint8_t *tx, uint8_t *rx, size_t len)
{
    if (!s || s->fd < 0 || len == 0) return len == 0 ? 0 : -1;
    struct spi_ioc_transfer tr;
    memset(&tr, 0, sizeof tr);
    tr.tx_buf        = (unsigned long)(uintptr_t)tx;
    tr.rx_buf        = (unsigned long)(uintptr_t)rx;
    tr.len           = (uint32_t)len;
    tr.speed_hz      = s->speed_hz;
    tr.bits_per_word = s->bits;
    tr.cs_change     = 0;

    for (;;) {
        int r = ioctl(s->fd, SPI_IOC_MESSAGE(1), &tr);
        if (r >= 0) return (int)len;
        if (errno == EINTR || errno == EAGAIN) continue;
        LOGE("spi: transfer errno %d (%s)", errno, strerror(errno));
        return -1;
    }
}

int nci_spi_write(nci_spi *s, const uint8_t *buf, size_t len)
{
    int n = spi_xfer(s, buf, NULL, len);
    if (n > 0) nci_log_hex_at(NCI_LVL_BYTES, "spi>", buf, (size_t)n);
    return n;
}

int nci_spi_read(nci_spi *s, uint8_t *buf, size_t len)
{
    int n = spi_xfer(s, NULL, buf, len);
    if (n > 0) nci_log_hex_at(NCI_LVL_BYTES, "spi<", buf, (size_t)n);
    return n;
}
