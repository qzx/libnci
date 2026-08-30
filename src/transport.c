/* SPDX-License-Identifier: Apache-2.0 */
/*
 * transport.c - Concrete I2C-or-SPI + libgpiod transport.
 *
 * Owns the byte-pipe (i2c OR spi) and gpio objects and implements the
 * nci_transport vtable:
 *   - reset(): the VEN/DWL choreography (ported from the old NfccReset)
 *   - read():  wait on IRQ edge, read the 3-byte NCI header, then the payload
 *              (the header-length rule from the old NfccAltI2cTransport::Read,
 *               minus the bogus select())
 *   - write(): one bus transaction (NCI control packets are <= 258 bytes)
 *
 * The byte-pipe is selected from cfg->bus_type: NCI_BUS_I2C uses i2c.c, NCI_BUS_SPI
 * uses spi.c. The NCI packet framing here is identical for both (impl.txt #117:
 * "same transport.c framing, different byte-pipe"); bus_read/bus_write dispatch to
 * the active pipe so the framing code below never branches on the bus.
 *
 * Also hosts the NXP firmware-download (DWL) protocol entry points (impl.txt #118):
 * in DWL mode the byte-pipe carries the NXP download frame format, not NCI, so those
 * functions reach the raw pipe directly. See transport.h for the frame layout and a
 * precise note on what is stubbed / unverified.
 */
#define _POSIX_C_SOURCE 200809L   /* nanosleep, clock_gettime */
#include "transport.h"
#include "gpio.h"
#include "i2c.h"
#include "nci_spi.h"
#include "log.h"
#include "nci/nci.h"   /* NCI_OK / nci_status codes for the DWL entry points */

#include <stdlib.h>
#include <string.h>
#include <time.h>

#define NCI_HEADER_LEN     3
#define NCI_LEN_OFFSET     2   /* payload length byte in an NCI packet */

typedef struct {
    nci_transport base;     /* must be first: &impl == &impl->base */
    int              bus_type;  /* nci_bus_type: which pipe below is live */
    nci_i2c         *i2c;       /* set when bus_type == NCI_BUS_I2C */
    nci_spi         *spi;       /* set when bus_type == NCI_BUS_SPI */
    nci_gpio        *gpio;
    unsigned int     settle_ms;
} transport_impl;

/* ---- byte-pipe dispatch (I2C vs SPI) ----------------------------------- *
 * The single place the bus type matters. Everything above these two helpers is
 * framing and is bus-agnostic. */
static int bus_write(transport_impl *t, const uint8_t *buf, size_t len)
{
    return t->bus_type == NCI_BUS_SPI ? nci_spi_write(t->spi, buf, len)
                                      : nci_i2c_write(t->i2c, buf, len);
}

static int bus_read(transport_impl *t, uint8_t *buf, size_t len)
{
    return t->bus_type == NCI_BUS_SPI ? nci_spi_read(t->spi, buf, len)
                                      : nci_i2c_read(t->i2c, buf, len);
}

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

static int drain_pending(transport_impl *t);   /* fwd: used by the SPI standby wake below */

/* Is this the start of a real received packet (RSP 0x4x / NTF 0x6x, MT bit7 clear) rather
 * than an idle line (0xFF, bit7 set)? */
static inline int looks_like_pkt(uint8_t b0) { return (b0 & 0x80) == 0; }

/* ---- vtable: reset ------------------------------------------------ */
static int t_reset(void *ctx, bool fw_download)
{
    transport_impl *t = ctx;
    LOGD("reset: fw_download=%d", fw_download);
    nci_gpio_set_dwl(t->gpio, fw_download);
    /* Power-down reset matching the empirically-proven qzx_spi_bringup sequence for this board:
     * drive VEN LOW long enough to fully power the NFCC down, then HIGH to boot. The controller
     * resets on the LOW *level* (a power-down), not an edge - so a long low is the software
     * equivalent of a power cycle and is what recovers a wedged controller; no leading HIGH pulse
     * is needed. (Proven: VEN LOW 300 ms -> HIGH 150 ms. The vendor uses the same low->high, just
     * a shorter hold.) */
    nci_gpio_set_ven(t->gpio, false);   /* VEN LOW: power down / reset */
    { unsigned int low = t->settle_ms; msleep(low < 300 ? 300 : low); }
    nci_gpio_set_ven(t->gpio, true);    /* VEN HIGH: boot */
    /* Let the firmware boot before ANY bus activity. The NFCC then sits in standby; the wake
     * (first write NAK'd, resend to land) is handled per-command in the NCI command() retry. */
    { unsigned int boot = t->settle_ms; msleep(boot < 150 ? 150 : boot); }
    return 0;
}

/* Drain one pending NCI packet (header + payload) and discard it. Used to
 * clear the half-duplex bus when the NFCC holds it to send while we want to
 * write. Returns the packet length, or <=0 if nothing was read. */
static int drain_pending(transport_impl *t)
{
    uint8_t buf[NCI_HEADER_LEN + 255];
    if (t->bus_type == NCI_BUS_SPI) {
        /* nci_spi_read returns one exact-length packet (header + payload) per call. */
        int n = bus_read(t, buf, sizeof buf);
        if (n < NCI_HEADER_LEN || !looks_like_pkt(buf[0])) return 0;
        nci_log_hex("DRAIN", buf, n);
        return n;
    }
    int n = bus_read(t, buf, NCI_HEADER_LEN);
    if (n != NCI_HEADER_LEN) return n;
    size_t payload = buf[NCI_LEN_OFFSET];
    if (payload) bus_read(t, buf + NCI_HEADER_LEN, payload);
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
     * packet (when IRQ is high) or briefly back off, then retry. (On SPI the
     * NAK-retry is harmless: a good write returns len on the first pass.) */
    for (int attempt = 0; attempt < 6; attempt++) {
        int n = bus_write(t, buf, len);
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

    if (t->bus_type == NCI_BUS_SPI) {
        /* Poll IRQ + read across the WHOLE timeout, exactly like the vendor's getMessage loop:
         * while not timed out, if IRQ says a packet is staged, read one; keep going on an idle/
         * not-ready read. This tolerates a packet that arrives late (e.g. the CORE_RESET_NTF a
         * few ms after the RSP) instead of giving up after a fixed number of tries. */
        for (int ms = 0; ms < timeout_ms; ms++) {
            int irq = nci_gpio_wait_irq(t->gpio, 1);      /* ~1 ms poll step */
            if (irq == NCI_GPIO_ABORTED) return NCI_TRANSPORT_ABORTED;
            if (irq == 1) {
                int n = bus_read(t, buf, cap);            /* one exact-length packet, or 0 if idle */
                if (n >= NCI_HEADER_LEN && looks_like_pkt(buf[0])) {
                    nci_log_hex("RECV", buf, n);
                    return n;
                }
                if (n < 0) return -1;
            }
        }
        return 0;                                         /* nothing within the window: caller resends */
    }

    /* I2C: wait IRQ, then header + payload (IRQ stays asserted until the packet is drained). */
    int irq = nci_gpio_wait_irq(t->gpio, timeout_ms);
    if (irq == 0) return 0;
    if (irq == NCI_GPIO_ABORTED) return NCI_TRANSPORT_ABORTED;
    if (irq < 0) return -1;

    int n = bus_read(t, buf, NCI_HEADER_LEN);
    if (n != NCI_HEADER_LEN) { LOGE("transport: header read %d", n); return -1; }
    size_t payload = buf[NCI_LEN_OFFSET];
    size_t total = NCI_HEADER_LEN + payload;
    if (total > cap) { LOGE("transport: packet len %zu exceeds buffer %zu", total, cap); return -1; }
    if (payload > 0) {
        n = bus_read(t, buf + NCI_HEADER_LEN, payload);
        if (n != (int)payload) { LOGE("transport: payload read %d/%zu", n, payload); return -1; }
    }
    nci_log_hex("RECV", buf, total);
    return (int)total;
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
    t->bus_type  = cfg->bus_type;

    nci_gpio_config gc = {
        .chip_path  = cfg->gpio_chip,
        .ven_offset = cfg->ven_offset,
        .irq_offset = cfg->irq_offset,
        .dwl_offset = cfg->dwl_offset,
    };
    t->gpio = nci_gpio_open(&gc);
    if (!t->gpio) goto fail;

    /* Open the byte-pipe selected by cfg->bus_type. i2c_bus doubles as the SPI
     * dev path (e.g. "/dev/spidev0.0"); SPI mode 0 is the PN7160 default. */
    if (cfg->bus_type == NCI_BUS_SPI) {
        t->spi = nci_spi_open(cfg->i2c_bus, cfg->spi_speed_hz, 0 /* SPI_MODE_0 */);
        if (!t->spi) goto fail;
    } else {
        t->i2c = nci_i2c_open(cfg->i2c_bus, cfg->i2c_addr);
        if (!t->i2c) goto fail;
    }

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
    if (t->spi)  nci_spi_close(t->spi);
    if (t->gpio) nci_gpio_close(t->gpio);
    free(t);
}

/* ==================================================================== *
 *  PN7160/PN71xx firmware download (DWL) protocol (impl.txt #118)
 *
 *  In DWL mode the controller speaks the NXP download format, not NCI:
 *      host -> NFCC : [LEN_HI LEN_LO] [CMD]    [DATA...] [CRC16_HI CRC16_LO]
 *      NFCC -> host : [LEN_HI LEN_LO] [STATUS] [DATA...] [CRC16_HI CRC16_LO]
 *  LEN counts the bytes after it (CMD/STATUS + DATA + CRC). CRC16 is CRC-16-CCITT
 *  over LEN+CMD/STATUS+DATA. These bypass the NCI header framing and use the raw
 *  byte-pipe. STUBBED / UNVERIFIED items are called out in transport.h.
 * ==================================================================== */

#define DWL_MAX_DATA   512     /* per-frame DATA cap (chunking is the caller's job) */

/* NXP download command IDs (phDnldNfc). UNVERIFIED opcode values - confirm
 * against UM11495 before driving real silicon. */
#define DWL_CMD_RESET       0xF0
#define DWL_CMD_GETVERSION  0xF1
#define DWL_CMD_WRITE       0xC0

/* CRC-16-CCITT (poly 0x1021, seed 0xFFFF, no reflection). The seed is part of
 * the UNVERIFIED set noted in transport.h. */
static uint16_t dwl_crc16(const uint8_t *p, size_t n)
{
    uint16_t crc = 0xFFFF;
    for (size_t i = 0; i < n; i++) {
        crc ^= (uint16_t)p[i] << 8;
        for (int b = 0; b < 8; b++)
            crc = (crc & 0x8000) ? (uint16_t)((crc << 1) ^ 0x1021)
                                 : (uint16_t)(crc << 1);
    }
    return crc;
}

/* Assemble one download frame [LEN][cmd][data][crc16] and transmit it. */
static int dwl_send(transport_impl *t, uint8_t cmd,
                    const uint8_t *data, size_t dlen)
{
    if (dlen > DWL_MAX_DATA) return NCI_E_INVAL;
    uint8_t f[2 + 1 + DWL_MAX_DATA + 2];
    size_t  body = 1 + dlen + 2;                 /* cmd + data + crc */
    f[0] = (uint8_t)(body >> 8);
    f[1] = (uint8_t)(body & 0xFF);
    f[2] = cmd;
    if (dlen) memcpy(&f[3], data, dlen);
    uint16_t crc = dwl_crc16(f, 3 + dlen);       /* over len+cmd+data */
    f[3 + dlen]     = (uint8_t)(crc >> 8);
    f[3 + dlen + 1] = (uint8_t)(crc & 0xFF);
    size_t total = 3 + dlen + 2;
    nci_log_hex_at(NCI_LVL_NCI, "DWL>", f, total);
    return bus_write(t, f, total) == (int)total ? NCI_OK : NCI_E_IO;
}

/* Read one download response frame after the IRQ edge, verify its CRC and
 * status, and copy the DATA field (after status, before crc) to out. */
static int dwl_recv(transport_impl *t, uint8_t *out, size_t cap, size_t *out_len)
{
    if (out_len) *out_len = 0;

    int irq = nci_gpio_wait_irq(t->gpio, 1000);
    if (irq == 0)                 return NCI_E_TIMEOUT;
    if (irq == NCI_GPIO_ABORTED)  return NCI_E_ABORTED;
    if (irq < 0)                  return NCI_E_IO;

    uint8_t hdr[2];
    if (bus_read(t, hdr, 2) != 2) return NCI_E_IO;
    size_t body = ((size_t)hdr[0] << 8) | hdr[1];   /* status + data + crc */
    if (body < 3)                 return NCI_E_PROTO;     /* need status + crc */

    uint8_t buf[1 + DWL_MAX_DATA + 2];
    if (body > sizeof buf)        return NCI_E_OVERFLOW;
    if (bus_read(t, buf, body) != (int)body) return NCI_E_IO;
    nci_log_hex_at(NCI_LVL_NCI, "DWL<", buf, body);

    /* CRC over len + status + data (everything but the trailing crc). */
    uint8_t crcin[2 + 1 + DWL_MAX_DATA];
    memcpy(crcin, hdr, 2);
    memcpy(crcin + 2, buf, body - 2);
    uint16_t want = ((uint16_t)buf[body - 2] << 8) | buf[body - 1];
    if (dwl_crc16(crcin, 2 + (body - 2)) != want) {
        LOGE("dwl: response CRC mismatch");
        return NCI_E_PROTO;
    }
    if (buf[0] != 0x00) {                            /* status byte */
        LOGE("dwl: response status 0x%02x", buf[0]);
        return NCI_E_STATUS;
    }

    size_t dlen = body - 3;                          /* minus status + crc */
    if (dlen) {
        if (!out || dlen > cap) return NCI_E_OVERFLOW;
        memcpy(out, buf + 1, dlen);
    }
    if (out_len) *out_len = dlen;
    return NCI_OK;
}

int nci_dwl_enter(nci_transport *t)
{
    if (!t) return NCI_E_INVAL;
    LOGD("dwl: entering firmware-download mode");
    return t->reset(t->ctx, true) == 0 ? NCI_OK : NCI_E_IO;   /* DWL pin high + VEN cycle */
}

int nci_dwl_leave(nci_transport *t)
{
    if (!t) return NCI_E_INVAL;
    transport_impl *ti = (transport_impl *)t;
    int rc = dwl_send(ti, DWL_CMD_RESET, NULL, 0);   /* download RESET */
    (void)dwl_recv(ti, NULL, 0, NULL);               /* best-effort ack; reset may pre-empt it */
    if (t->reset(t->ctx, false) != 0) return NCI_E_IO;   /* normal (DWL low) boot -> back on NCI */
    return rc;
}

int nci_dwl_get_version(nci_transport *t, uint8_t *out, size_t cap, size_t *out_len)
{
    if (!t) return NCI_E_INVAL;
    transport_impl *ti = (transport_impl *)t;
    int rc = dwl_send(ti, DWL_CMD_GETVERSION, NULL, 0);
    if (rc != NCI_OK) return rc;
    return dwl_recv(ti, out, cap, out_len);
}

int nci_dwl_write_chunk(nci_transport *t, const uint8_t *chunk, size_t len)
{
    if (!t || (!chunk && len)) return NCI_E_INVAL;
    transport_impl *ti = (transport_impl *)t;
    int rc = dwl_send(ti, DWL_CMD_WRITE, chunk, len);
    if (rc != NCI_OK) return rc;
    return dwl_recv(ti, NULL, 0, NULL);              /* per-chunk WRITE ack */
}
