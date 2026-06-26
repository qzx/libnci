/* SPDX-License-Identifier: Apache-2.0 */
/*
 * transport.c - Concrete I2C + libgpiod transport.
 *
 * Owns the i2c and gpio objects and implements the pn7160_transport vtable:
 *   - reset(): the VEN/DWL choreography (ported from the old NfccReset)
 *   - read():  wait on IRQ edge, read the 3-byte NCI header, then the payload
 *              (the header-length rule from the old NfccAltI2cTransport::Read,
 *               minus the bogus select())
 *   - write(): one I2C transaction (NCI control packets are <= 258 bytes)
 */
#define _POSIX_C_SOURCE 200809L   /* nanosleep, clock_gettime */
#include "transport.h"
#include "gpio.h"
#include "i2c.h"
#include "log.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

#define NCI_HEADER_LEN     3
#define NCI_LEN_OFFSET     2   /* payload length byte in an NCI packet */

typedef struct {
    pn7160_transport base;     /* must be first: &impl == &impl->base */
    pn7160_i2c      *i2c;
    pn7160_gpio     *gpio;
    unsigned int     settle_ms;
} transport_impl;

static void msleep(unsigned int ms)
{
    struct timespec ts = { ms / 1000, (long)(ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
}

/* ---- vtable: reset ------------------------------------------------ */
static int t_reset(void *ctx, bool fw_download)
{
    transport_impl *t = ctx;
    LOGD("reset: fw_download=%d", fw_download);
    pn7160_gpio_set_dwl(t->gpio, fw_download);
    msleep(t->settle_ms);
    pn7160_gpio_set_ven(t->gpio, false);   /* power off / assert reset */
    msleep(t->settle_ms);
    pn7160_gpio_set_ven(t->gpio, true);    /* release reset -> boot    */
    msleep(t->settle_ms * 2);              /* let the bootloader settle */
    return 0;
}

/* ---- vtable: write ----------------------------------------------- */
static int t_write(void *ctx, const uint8_t *buf, size_t len)
{
    transport_impl *t = ctx;
    pn7160_log_hex("SEND", buf, len);
    int n = pn7160_i2c_write(t->i2c, buf, len);
    if (n != (int)len) {
        LOGE("transport: short write %d/%zu", n, len);
        return -1;
    }
    return n;
}

/* ---- vtable: read ------------------------------------------------ */
static int t_read(void *ctx, uint8_t *buf, size_t cap, int timeout_ms)
{
    transport_impl *t = ctx;
    if (cap < NCI_HEADER_LEN) return -1;

    int irq = pn7160_gpio_wait_irq(t->gpio, timeout_ms);
    if (irq == 0) return 0;            /* timeout: no data pending */
    if (irq < 0)  return -1;

    /* Header: MT/PBF/GID, OID, payload length. */
    int n = pn7160_i2c_read(t->i2c, buf, NCI_HEADER_LEN);
    if (n != NCI_HEADER_LEN) {
        LOGE("transport: header read %d", n);
        return -1;
    }
    size_t payload = buf[NCI_LEN_OFFSET];
    if (NCI_HEADER_LEN + payload > cap) {
        LOGE("transport: packet len %zu exceeds buffer %zu",
             NCI_HEADER_LEN + payload, cap);
        return -1;
    }
    if (payload > 0) {
        /* IRQ stays asserted until the whole packet is drained, so the
         * payload is already available - no second edge to wait for. */
        n = pn7160_i2c_read(t->i2c, buf + NCI_HEADER_LEN, payload);
        if (n != (int)payload) {
            LOGE("transport: payload read %d/%zu", n, payload);
            return -1;
        }
    }
    pn7160_log_hex("RECV", buf, NCI_HEADER_LEN + payload);
    return (int)(NCI_HEADER_LEN + payload);
}

/* ---- lifecycle --------------------------------------------------- */
pn7160_transport *pn7160_transport_open(const pn7160_config *cfg)
{
    if (!cfg) return NULL;
    transport_impl *t = calloc(1, sizeof *t);
    if (!t) return NULL;
    t->settle_ms = cfg->reset_settle_ms ? cfg->reset_settle_ms : 10;

    pn7160_gpio_config gc = {
        .chip_path  = cfg->gpio_chip,
        .ven_offset = cfg->ven_offset,
        .irq_offset = cfg->irq_offset,
        .dwl_offset = cfg->dwl_offset,
    };
    t->gpio = pn7160_gpio_open(&gc);
    if (!t->gpio) goto fail;

    t->i2c = pn7160_i2c_open(cfg->i2c_bus, cfg->i2c_addr);
    if (!t->i2c) goto fail;

    t->base.ctx   = t;
    t->base.write = t_write;
    t->base.read  = t_read;
    t->base.reset = t_reset;
    return &t->base;
fail:
    pn7160_transport_close(&t->base);
    return NULL;
}

void pn7160_transport_close(pn7160_transport *base)
{
    if (!base) return;
    transport_impl *t = (transport_impl *)base;
    if (t->i2c)  pn7160_i2c_close(t->i2c);
    if (t->gpio) pn7160_gpio_close(t->gpio);
    free(t);
}
