/* SPDX-License-Identifier: Apache-2.0 */
/*
 * gpio.c - libgpiod v2 implementation of the three PN7160 control lines.
 *
 * Replaces, in one file, everything the old NfccAltTransport spread across
 * ConfigurePin(), gpio_set_ven(), gpio_set_fwdl(), wait4interrupt(),
 * GetIrqState(), the dead /sys/class/gpio block and four file-scope globals.
 *
 * Key behavioural change vs the old code: IRQ is edge-driven. The old driver
 * did `while (gpiod_line_get_value(IRQ) != 1) {}` which pins a CPU core. Here
 * we park in the kernel with gpiod_line_request_wait_edge_events().
 */
#include "gpio.h"
#include "log.h"

#include <gpiod.h>          /* <-- the ONLY place this is included */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

struct pn7160_gpio {
    struct gpiod_chip         *chip;
    struct gpiod_line_request *out_req;  /* VEN + DWL (outputs) */
    struct gpiod_line_request *irq_req;  /* IRQ (rising-edge input) */
    unsigned int ven, dwl, irq;
    char path[64];
};

/* ------------------------------------------------------------------ *
 * Controller auto-detection
 *
 * On a Pi 5 the 40-pin header lives on RP1 (label "pinctrl-rp1"); on a
 * Pi 4 / 3 / Zero it is on the SoC (label "pinctrl-bcm2711" / "...2835").
 * Guessing a chip *number* is fragile across OS images, so we match by
 * label instead. RP1 is preferred when present.
 * ------------------------------------------------------------------ */
static bool chip_label_is_header(const char *label)
{
    if (!label) return false;
    return strstr(label, "pinctrl-rp1") || strstr(label, "pinctrl-bcm") ||
           strstr(label, "bcm2835")     || strstr(label, "bcm2711")     ||
           strstr(label, "bcm2712");
}

static bool read_chip_label(const char *path, char *out, size_t out_sz)
{
    struct gpiod_chip *c = gpiod_chip_open(path);
    if (!c) return false;
    bool ok = false;
    struct gpiod_chip_info *info = gpiod_chip_get_info(c);
    if (info) {
        const char *label = gpiod_chip_info_get_label(info);
        if (label) { snprintf(out, out_sz, "%s", label); ok = true; }
        gpiod_chip_info_free(info);
    }
    gpiod_chip_close(c);
    return ok;
}

static bool autodetect_chip(char *out, size_t out_sz)
{
    char best_rp1[64] = {0};
    char best_any[64] = {0};
    for (int i = 0; i < 32; i++) {
        char path[64], label[64];
        snprintf(path, sizeof path, "/dev/gpiochip%d", i);
        if (!read_chip_label(path, label, sizeof label))
            continue;
        if (strstr(label, "pinctrl-rp1") && !best_rp1[0])
            snprintf(best_rp1, sizeof best_rp1, "%s", path);
        else if (chip_label_is_header(label) && !best_any[0])
            snprintf(best_any, sizeof best_any, "%s", path);
    }
    const char *pick = best_rp1[0] ? best_rp1 : (best_any[0] ? best_any : NULL);
    if (!pick) return false;
    snprintf(out, out_sz, "%s", pick);
    return true;
}

/* ------------------------------------------------------------------ *
 * Line requests
 * ------------------------------------------------------------------ */
static struct gpiod_line_request *
request_outputs(struct gpiod_chip *chip, unsigned int ven, unsigned int dwl)
{
    struct gpiod_line_settings  *s  = gpiod_line_settings_new();
    struct gpiod_line_config    *lc = gpiod_line_config_new();
    struct gpiod_request_config *rc = gpiod_request_config_new();
    struct gpiod_line_request   *req = NULL;
    if (!s || !lc || !rc) goto out;

    gpiod_line_settings_set_direction(s, GPIOD_LINE_DIRECTION_OUTPUT);
    gpiod_line_settings_set_output_value(s, GPIOD_LINE_VALUE_INACTIVE);

    unsigned int offs[2] = { ven, dwl };
    if (gpiod_line_config_add_line_settings(lc, offs, 2, s) < 0) goto out;

    gpiod_request_config_set_consumer(rc, "pn7160-ctrl");
    req = gpiod_chip_request_lines(chip, rc, lc);
out:
    gpiod_request_config_free(rc);
    gpiod_line_config_free(lc);
    gpiod_line_settings_free(s);
    return req;
}

static struct gpiod_line_request *
request_irq(struct gpiod_chip *chip, unsigned int irq)
{
    struct gpiod_line_settings  *s  = gpiod_line_settings_new();
    struct gpiod_line_config    *lc = gpiod_line_config_new();
    struct gpiod_request_config *rc = gpiod_request_config_new();
    struct gpiod_line_request   *req = NULL;
    if (!s || !lc || !rc) goto out;

    gpiod_line_settings_set_direction(s, GPIOD_LINE_DIRECTION_INPUT);
    gpiod_line_settings_set_edge_detection(s, GPIOD_LINE_EDGE_RISING);
    /* PN7160 IRQ is a push-pull active-high output; no host bias needed. */
    gpiod_line_settings_set_bias(s, GPIOD_LINE_BIAS_DISABLED);

    unsigned int offs[1] = { irq };
    if (gpiod_line_config_add_line_settings(lc, offs, 1, s) < 0) goto out;

    gpiod_request_config_set_consumer(rc, "pn7160-irq");
    req = gpiod_chip_request_lines(chip, rc, lc);
out:
    gpiod_request_config_free(rc);
    gpiod_line_config_free(lc);
    gpiod_line_settings_free(s);
    return req;
}

/* ------------------------------------------------------------------ *
 * Public API
 * ------------------------------------------------------------------ */
pn7160_gpio *pn7160_gpio_open(const pn7160_gpio_config *cfg)
{
    if (!cfg) return NULL;
    pn7160_gpio *g = calloc(1, sizeof *g);
    if (!g) return NULL;
    g->ven = cfg->ven_offset;
    g->dwl = cfg->dwl_offset;
    g->irq = cfg->irq_offset;

    if (cfg->chip_path && cfg->chip_path[0]) {
        snprintf(g->path, sizeof g->path, "%s", cfg->chip_path);
    } else if (!autodetect_chip(g->path, sizeof g->path)) {
        LOGE("gpio: could not auto-detect a GPIO controller");
        goto fail;
    }

    g->chip = gpiod_chip_open(g->path);
    if (!g->chip) {
        LOGE("gpio: open %s failed (check permissions / 'gpio' group)", g->path);
        goto fail;
    }
    g->out_req = request_outputs(g->chip, g->ven, g->dwl);
    if (!g->out_req) {
        LOGE("gpio: request VEN(%u)/DWL(%u) as outputs failed (line busy?)",
             g->ven, g->dwl);
        goto fail;
    }
    g->irq_req = request_irq(g->chip, g->irq);
    if (!g->irq_req) {
        LOGE("gpio: request IRQ(%u) input+edge failed (line busy?)", g->irq);
        goto fail;
    }
    LOGD("gpio: %s VEN=%u IRQ=%u DWL=%u", g->path, g->ven, g->irq, g->dwl);
    return g;
fail:
    pn7160_gpio_close(g);
    return NULL;
}

void pn7160_gpio_close(pn7160_gpio *g)
{
    if (!g) return;
    if (g->irq_req) gpiod_line_request_release(g->irq_req);
    if (g->out_req) gpiod_line_request_release(g->out_req);
    if (g->chip)    gpiod_chip_close(g->chip);
    free(g);
}

static void set_line(struct gpiod_line_request *req, unsigned int off, bool high)
{
    if (!req) return;
    gpiod_line_request_set_value(req, off,
        high ? GPIOD_LINE_VALUE_ACTIVE : GPIOD_LINE_VALUE_INACTIVE);
}

void pn7160_gpio_set_ven(pn7160_gpio *g, bool high)
{
    if (g) set_line(g->out_req, g->ven, high);
}

void pn7160_gpio_set_dwl(pn7160_gpio *g, bool high)
{
    if (g) set_line(g->out_req, g->dwl, high);
}

int pn7160_gpio_wait_irq(pn7160_gpio *g, int timeout_ms)
{
    if (!g || !g->irq_req) return -1;

    /* The chip holds IRQ high while a packet is pending. If we already
     * missed the edge (line is high now) report ready immediately so we
     * never deadlock waiting for an edge that has already passed. */
    if (gpiod_line_request_get_value(g->irq_req, g->irq) == GPIOD_LINE_VALUE_ACTIVE)
        return 1;

    int64_t timeout_ns = (timeout_ms < 0) ? -1 : (int64_t)timeout_ms * 1000000;
    int r = gpiod_line_request_wait_edge_events(g->irq_req, timeout_ns);
    if (r <= 0) return r;   /* 0 timeout, <0 error */

    /* Drain the edge events so the next wait blocks correctly. */
    struct gpiod_edge_event_buffer *buf = gpiod_edge_event_buffer_new(8);
    if (buf) {
        gpiod_line_request_read_edge_events(g->irq_req, buf, 8);
        gpiod_edge_event_buffer_free(buf);
    }
    return 1;
}

int pn7160_gpio_read_irq(pn7160_gpio *g)
{
    if (!g || !g->irq_req) return -1;
    enum gpiod_line_value v = gpiod_line_request_get_value(g->irq_req, g->irq);
    if (v == GPIOD_LINE_VALUE_ERROR) return -1;
    return v == GPIOD_LINE_VALUE_ACTIVE ? 1 : 0;
}

const char *pn7160_gpio_chip_path(pn7160_gpio *g)
{
    return g ? g->path : "";
}
