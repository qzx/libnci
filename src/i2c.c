/* SPDX-License-Identifier: Apache-2.0 */
/*
 * i2c.c - /dev/i2c-N transport. Mirrors the working parts of the old
 * NfccAltI2cTransport (open, I2C_SLAVE ioctl, read/write) without the
 * meaningless select() on a char-dev fd: readiness is signalled by the
 * IRQ GPIO, handled in the transport layer.
 */
#define _POSIX_C_SOURCE 200809L   /* nanosleep */
#include "i2c.h"
#include "log.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/i2c-dev.h>

/* The PN7160 occasionally NAKs an I2C read (EREMOTEIO) when the host reads a
 * hair before the data is latched, even with IRQ asserted. NXP's own HAL
 * retries this; a few short retries smooth it over without masking a removed
 * chip (after the budget we still surface the error). */
#define I2C_READ_RETRIES 8
#define I2C_RETRY_US     200

struct nci_i2c {
    int      fd;
    uint16_t addr;
};

nci_i2c *nci_i2c_open(const char *bus, uint16_t addr)
{
    if (!bus) return NULL;
    nci_i2c *i = calloc(1, sizeof *i);
    if (!i) return NULL;
    i->addr = addr;

    i->fd = open(bus, O_RDWR | O_NOCTTY);
    if (i->fd < 0) {
        LOGE("i2c: open %s failed: %s (in 'i2c' group? dtparam=i2c_arm=on?)",
             bus, strerror(errno));
        free(i);
        return NULL;
    }
    if (ioctl(i->fd, I2C_SLAVE, addr) < 0) {
        LOGE("i2c: select addr 0x%02x failed: %s", addr, strerror(errno));
        close(i->fd);
        free(i);
        return NULL;
    }
    LOGD("i2c: %s addr 0x%02x open (fd %d)", bus, addr, i->fd);
    return i;
}

void nci_i2c_close(nci_i2c *i)
{
    if (!i) return;
    if (i->fd >= 0) close(i->fd);
    free(i);
}

int nci_i2c_write(nci_i2c *i, const uint8_t *buf, size_t len)
{
    if (!i || i->fd < 0) return -1;
    int eremoteio = 0;
    for (;;) {
        ssize_t n = write(i->fd, buf, len);
        if (n >= 0) { nci_log_hex_at(NCI_LVL_BYTES, "i2c>", buf, (size_t)n); return (int)n; }
        if (errno == EINTR || errno == EAGAIN) continue;
        /* The PN7160 transiently NAKs a write too (e.g. just after a state
         * change); retry briefly as on the read path before giving up. */
        if (errno == EREMOTEIO && eremoteio++ < I2C_READ_RETRIES) {
            struct timespec ts = { 0, I2C_RETRY_US * 1000L };
            nanosleep(&ts, NULL);
            continue;
        }
        LOGE("i2c: write errno %d (%s)", errno, strerror(errno));
        return -1;
    }
}

int nci_i2c_read(nci_i2c *i, uint8_t *buf, size_t len)
{
    if (!i || i->fd < 0) return -1;
    int eremoteio = 0;
    for (;;) {
        ssize_t n = read(i->fd, buf, len);
        if (n >= 0) { nci_log_hex_at(NCI_LVL_BYTES, "i2c<", buf, (size_t)n); return (int)n; }
        if (errno == EINTR || errno == EAGAIN) continue;
        if (errno == EREMOTEIO && eremoteio++ < I2C_READ_RETRIES) {
            struct timespec ts = { 0, I2C_RETRY_US * 1000L };
            nanosleep(&ts, NULL);
            continue;
        }
        LOGE("i2c: read errno %d (%s)", errno, strerror(errno));
        return -1;
    }
}
