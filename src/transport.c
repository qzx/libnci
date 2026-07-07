/* SPDX-License-Identifier: Apache-2.0 */
/*
 * transport.c - Concrete I2C + libgpiod transport.
 *
 * Owns the i2c and gpio objects and implements the nci_transport vtable:
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
    nci_transport base;     /* must be first: &impl == &impl->base */
    nci_i2c      *i2c;
    nci_gpio     *gpio;
    unsigned int     settle_ms;
} transport_impl;

#if defined(ESP_PLATFORM) || defined(ARDUINO)
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#endif

static void msleep(unsigned int ms)
{
#if defined(ESP_PLATFORM) || defined(ARDUINO)
    /* The ESP32 newlib-nano doesn't link nanosleep; FreeRTOS vTaskDelay is the right sleep here
     * (it yields the scheduler instead of busy-waiting), with a 1-tick floor so a short delay
     * still yields. */
    TickType_t t = pdMS_TO_TICKS(ms);
    vTaskDelay(t ? t : 1);
#else
    struct timespec ts = { ms / 1000, (long)(ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
#endif
}

/* ---- vtable: reset ------------------------------------------------ */
static int t_reset(void *ctx, bool fw_download)
{
    transport_impl *t = ctx;
    LOGD("reset: fw_download=%d", fw_download);
    nci_gpio_set_dwl(t->gpio, fw_download);
    msleep(t->settle_ms);
    nci_gpio_set_ven(t->gpio, false);   /* power off / assert reset */
    msleep(t->settle_ms);
    nci_gpio_set_ven(t->gpio, true);    /* release reset -> boot    */
    msleep(t->settle_ms * 2);              /* let the bootloader settle */
    return 0;
}

/* Drain one pending NCI packet (header + payload) and discard it. Used to
 * clear the half-duplex bus when the NFCC holds it to send while we want to
 * write. Returns the packet length, or <=0 if nothing was read. */
static int drain_pending(transport_impl *t)
{
    uint8_t buf[NCI_HEADER_LEN + 255];
    int n = nci_i2c_read(t->i2c, buf, NCI_HEADER_LEN);
    if (n != NCI_HEADER_LEN) return n;
    size_t payload = buf[NCI_LEN_OFFSET];
    if (payload) nci_i2c_read(t->i2c, buf + NCI_HEADER_LEN, payload);
    nci_log_hex("DRAIN", buf, NCI_HEADER_LEN + payload);
    return (int)(NCI_HEADER_LEN + payload);
}

/* ---- vtable: write ----------------------------------------------- */
static int t_write(void *ctx, const uint8_t *buf, size_t len)
{
    transport_impl *t = ctx;
    nci_log_hex("SEND", buf, len);

    /* The PN7160 I2C bus is half-duplex: while the NFCC has a packet to send
     * (IRQ asserted) it NAKs host writes. If a write fails, drain a pending
     * packet (when IRQ is high) or briefly back off, then retry. */
    for (int attempt = 0; attempt < 6; attempt++) {
        int n = nci_i2c_write(t->i2c, buf, len);
        if (n == (int)len) return n;
        if (nci_gpio_read_irq(t->gpio) == 1)
            drain_pending(t);
        else
            msleep(2);
    }
    LOGE("transport: write to NFCC failed (bus busy)");
    return -1;
}

/* ---- vtable: read ------------------------------------------------ */
static int t_read(void *ctx, uint8_t *buf, size_t cap, int timeout_ms)
{
    transport_impl *t = ctx;
    if (cap < NCI_HEADER_LEN) return -1;

    int irq = nci_gpio_wait_irq(t->gpio, timeout_ms);
    if (irq == 0) return 0;            /* timeout: no data pending */
    if (irq == NCI_GPIO_ABORTED) return NCI_TRANSPORT_ABORTED;
    if (irq < 0)  return -1;

    /* Header: MT/PBF/GID, OID, payload length. */
    int n = nci_i2c_read(t->i2c, buf, NCI_HEADER_LEN);
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
        n = nci_i2c_read(t->i2c, buf + NCI_HEADER_LEN, payload);
        if (n != (int)payload) {
            LOGE("transport: payload read %d/%zu", n, payload);
            return -1;
        }
    }
    nci_log_hex("RECV", buf, NCI_HEADER_LEN + payload);
    return (int)(NCI_HEADER_LEN + payload);
}

/* ---- vtable: abort ----------------------------------------------- */
static void t_abort(void *ctx)
{
    transport_impl *t = ctx;
    nci_gpio_abort(t->gpio);
}

/* ---- lifecycle --------------------------------------------------- */
nci_transport *nci_transport_open(const nci_config *cfg)
{
    if (!cfg) return NULL;
    transport_impl *t = calloc(1, sizeof *t);
    if (!t) return NULL;
    t->settle_ms = cfg->reset_settle_ms ? cfg->reset_settle_ms : 10;

    nci_gpio_config gc = {
        .chip_path  = cfg->gpio_chip,
        .ven_offset = cfg->ven_offset,
        .irq_offset = cfg->irq_offset,
        .dwl_offset = cfg->dwl_offset,
    };
    t->gpio = nci_gpio_open(&gc);
    if (!t->gpio) goto fail;

    t->i2c = nci_i2c_open(cfg->i2c_bus, cfg->i2c_addr);
    if (!t->i2c) goto fail;

    t->base.ctx   = t;
    t->base.write = t_write;
    t->base.read  = t_read;
    t->base.reset = t_reset;
    t->base.abort = t_abort;
    return &t->base;
fail:
    nci_transport_close(&t->base);
    return NULL;
}

void nci_transport_close(nci_transport *base)
{
    if (!base) return;
    transport_impl *t = (transport_impl *)base;
    if (t->i2c)  nci_i2c_close(t->i2c);
    if (t->gpio) nci_gpio_close(t->gpio);
    free(t);
}
