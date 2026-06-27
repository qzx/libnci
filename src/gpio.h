/* SPDX-License-Identifier: Apache-2.0 */
/*
 * gpio.h - Layer 1: the GPIO control lines (VEN, IRQ, DWL).
 *
 * This is the ONLY part of the codebase that knows libgpiod exists. The rest
 * of the stack sees "set VEN", "wait for IRQ" - never a chip, line or event.
 * That quarantine is the whole point: when libgpiod bumps a version, or the
 * board changes controller, exactly one .c file changes.
 *
 * See doc/NCI_libgpiod2_library_design.md §4.2.
 */
#ifndef NCI_GPIO_H
#define NCI_GPIO_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct nci_gpio nci_gpio;   /* opaque */

typedef struct {
    const char  *chip_path;   /* "/dev/gpiochip4"; NULL/"" => auto-detect */
    unsigned int ven_offset;
    unsigned int irq_offset;
    unsigned int dwl_offset;
} nci_gpio_config;

/* Enumerate candidate header GPIO controllers (by label) in preference order
 * - "pinctrl-rp1" (Pi 5) first, then other SoC header controllers. Fills paths
 * (each a char[64]) and returns the count. Several chips can share a label on
 * Pi 5 (e.g. two "pinctrl-rp1"); the caller probes each until one answers. */
int nci_gpio_header_chips(char (*paths)[64], int max);

/* Request VEN+DWL as outputs (initially inactive) and IRQ as a
 * rising-edge input. Returns NULL on failure. */
nci_gpio *nci_gpio_open(const nci_gpio_config *cfg);
void         nci_gpio_close(nci_gpio *g);

void nci_gpio_set_ven(nci_gpio *g, bool high);
void nci_gpio_set_dwl(nci_gpio *g, bool high);

/* nci_gpio_wait_irq returns this when interrupted by nci_gpio_abort(). */
#define NCI_GPIO_ABORTED (-2)

/* Block until an IRQ rising edge, a timeout, or an abort.
 *   >0 : an edge arrived
 *    0 : timed out
 *   NCI_GPIO_ABORTED : interrupted by nci_gpio_abort()
 *   <0 : error
 * timeout_ms < 0 blocks indefinitely (still interruptible via abort). */
int nci_gpio_wait_irq(nci_gpio *g, int timeout_ms);

/* Wake a blocked wait_irq from another thread (one-shot). */
void nci_gpio_abort(nci_gpio *g);

/* Instantaneous IRQ level: 1 high, 0 low, <0 error. */
int nci_gpio_read_irq(nci_gpio *g);

/* The chip path actually in use (after any auto-detection). For logging. */
const char *nci_gpio_chip_path(nci_gpio *g);

#ifdef __cplusplus
}
#endif

#endif /* NCI_GPIO_H */
