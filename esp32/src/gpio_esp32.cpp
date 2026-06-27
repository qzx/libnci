/* SPDX-License-Identifier: Apache-2.0 */
/*
 * gpio_esp32.cpp - ESP32 GPIO control lines for libnci (replaces src/gpio.c).
 *
 * Implements gpio.h over the Arduino digital API. The libgpiod chip-path /
 * line-offset model maps to ESP32 GPIO pin numbers: ven/irq/dwl "offsets" in
 * nci_config are the GPIO pins. There is no chip enumeration on ESP32, so
 * nci_gpio_header_chips() returns 0 and nci_open() falls back to using the
 * configured pins directly.
 *
 * The PN7160 drives IRQ push-pull and holds it asserted (HIGH) while it has a
 * packet pending, so we level-poll the pin rather than wait for an edge - this
 * is simpler and robust. abort() is a flag checked in the poll loop.
 *
 * gpio.h declares these extern "C", so the definitions inherit C linkage.
 */
#include <Arduino.h>
#include <stdlib.h>
#include "gpio.h"

struct nci_gpio {
    int ven, irq, dwl;
    volatile bool abort_flag;
};

/* ESP32 has no GPIO-chip enumeration; let nci_open() use the configured pins. */
int nci_gpio_header_chips(char (*paths)[64], int max)
{
    (void)paths; (void)max;
    return 0;
}

nci_gpio *nci_gpio_open(const nci_gpio_config *cfg)
{
    if (!cfg) return NULL;
    nci_gpio *g = (nci_gpio *)calloc(1, sizeof(nci_gpio));
    if (!g) return NULL;
    g->ven = (int)cfg->ven_offset;
    g->irq = (int)cfg->irq_offset;
    g->dwl = (int)cfg->dwl_offset;
    pinMode(g->ven, OUTPUT);
    pinMode(g->dwl, OUTPUT);
    pinMode(g->irq, INPUT);              /* INPUT_PULLDOWN also works on most boards */
    digitalWrite(g->ven, LOW);          /* start with the NFCC held in reset/off */
    digitalWrite(g->dwl, LOW);
    g->abort_flag = false;
    return g;
}

void nci_gpio_close(nci_gpio *g)
{
    if (g) free(g);
}

void nci_gpio_set_ven(nci_gpio *g, bool high)
{
    if (g) digitalWrite(g->ven, high ? HIGH : LOW);
}

void nci_gpio_set_dwl(nci_gpio *g, bool high)
{
    if (g) digitalWrite(g->dwl, high ? HIGH : LOW);
}

int nci_gpio_read_irq(nci_gpio *g)
{
    if (!g) return -1;
    return digitalRead(g->irq) == HIGH ? 1 : 0;
}

/* Block until IRQ is asserted (HIGH), a timeout, or an abort. delay(1) yields
 * to FreeRTOS so the watchdog / WiFi stack stay happy during long polls. */
int nci_gpio_wait_irq(nci_gpio *g, int timeout_ms)
{
    if (!g) return -1;
    uint32_t start = millis();
    for (;;) {
        if (g->abort_flag) { g->abort_flag = false; return NCI_GPIO_ABORTED; }
        if (digitalRead(g->irq) == HIGH) return 1;
        if (timeout_ms >= 0 && (uint32_t)(millis() - start) >= (uint32_t)timeout_ms)
            return 0;
        delay(1);
    }
}

void nci_gpio_abort(nci_gpio *g)
{
    if (g) g->abort_flag = true;
}

const char *nci_gpio_chip_path(nci_gpio *g)
{
    (void)g;
    return "esp32-gpio";
}
