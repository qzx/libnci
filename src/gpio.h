/* SPDX-License-Identifier: Apache-2.0 */
/*
 * gpio.h - Layer 1: the GPIO control lines (VEN, IRQ, DWL).
 *
 * This is the ONLY part of the codebase that knows libgpiod exists. The rest
 * of the stack sees "set VEN", "wait for IRQ" - never a chip, line or event.
 * That quarantine is the whole point: when libgpiod bumps a version, or the
 * board changes controller, exactly one .c file changes.
 *
 * See doc/PN7160_libgpiod2_library_design.md §4.2.
 */
#ifndef PN7160_GPIO_H
#define PN7160_GPIO_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct pn7160_gpio pn7160_gpio;   /* opaque */

typedef struct {
    const char  *chip_path;   /* "/dev/gpiochip4"; NULL/"" => auto-detect */
    unsigned int ven_offset;
    unsigned int irq_offset;
    unsigned int dwl_offset;
} pn7160_gpio_config;

/* Request VEN+DWL as outputs (initially inactive) and IRQ as a
 * rising-edge input. Returns NULL on failure. */
pn7160_gpio *pn7160_gpio_open(const pn7160_gpio_config *cfg);
void         pn7160_gpio_close(pn7160_gpio *g);

void pn7160_gpio_set_ven(pn7160_gpio *g, bool high);
void pn7160_gpio_set_dwl(pn7160_gpio *g, bool high);

/* Block until an IRQ rising edge or timeout.
 *   >0 : an edge arrived
 *    0 : timed out
 *   <0 : error
 * timeout_ms < 0 blocks indefinitely. */
int pn7160_gpio_wait_irq(pn7160_gpio *g, int timeout_ms);

/* Instantaneous IRQ level: 1 high, 0 low, <0 error. */
int pn7160_gpio_read_irq(pn7160_gpio *g);

/* The chip path actually in use (after any auto-detection). For logging. */
const char *pn7160_gpio_chip_path(pn7160_gpio *g);

#ifdef __cplusplus
}
#endif

#endif /* PN7160_GPIO_H */
