/* SPDX-License-Identifier: Apache-2.0 */
/*
 * i2c.c - /dev/i2c-N transport. Mirrors the working parts of the old
 * NfccAltI2cTransport (open, I2C_SLAVE ioctl, read/write) without the
 * meaningless select() on a char-dev fd: readiness is signalled by the
 * IRQ GPIO, handled in the transport layer.
 */
#include "i2c.h"
#include "log.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/i2c-dev.h>

struct pn7160_i2c {
    int      fd;
    uint16_t addr;
};

pn7160_i2c *pn7160_i2c_open(const char *bus, uint16_t addr)
{
    if (!bus) return NULL;
    pn7160_i2c *i = calloc(1, sizeof *i);
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

void pn7160_i2c_close(pn7160_i2c *i)
{
    if (!i) return;
    if (i->fd >= 0) close(i->fd);
    free(i);
}

int pn7160_i2c_write(pn7160_i2c *i, const uint8_t *buf, size_t len)
{
    if (!i || i->fd < 0) return -1;
    for (;;) {
        ssize_t n = write(i->fd, buf, len);
        if (n >= 0) return (int)n;
        if (errno == EINTR || errno == EAGAIN) continue;
        LOGE("i2c: write errno %d (%s)", errno, strerror(errno));
        return -1;
    }
}

int pn7160_i2c_read(pn7160_i2c *i, uint8_t *buf, size_t len)
{
    if (!i || i->fd < 0) return -1;
    for (;;) {
        ssize_t n = read(i->fd, buf, len);
        if (n >= 0) return (int)n;
        if (errno == EINTR || errno == EAGAIN) continue;
        LOGE("i2c: read errno %d (%s)", errno, strerror(errno));
        return -1;
    }
}
