/* SPDX-License-Identifier: Apache-2.0 */
/*
 * pn7160_config.h - Runtime configuration for the PN7160 driver.
 *
 * Everything that the old NXP code baked in as #defines (pins, bus, address,
 * chip name) lives here as data, injected at pn7160_open(). Changing a pin or
 * moving between a Pi 4 and a Pi 5 is a config change, never a recompile.
 *
 * See doc/PN7160_libgpiod2_library_design.md §6.
 */
#ifndef PN7160_CONFIG_H
#define PN7160_CONFIG_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    /* I2C interface */
    const char *i2c_bus;        /* e.g. "/dev/i2c-1"                         */
    uint16_t    i2c_addr;       /* 7-bit slave address, PN7160 = 0x28        */

    /* GPIO (libgpiod v2). If gpio_chip is NULL or "", the chip is
     * auto-detected by controller label (pinctrl-rp1 on Pi 5,
     * pinctrl-bcm* on Pi 4 and earlier). */
    const char  *gpio_chip;     /* e.g. "/dev/gpiochip4" (Pi 5 RP1)          */
    unsigned int ven_offset;    /* VEN / reset   (BCM 24)                    */
    unsigned int irq_offset;    /* IRQ / data-ready, input (BCM 23)          */
    unsigned int dwl_offset;    /* DWL_REQ firmware boot (BCM 25; docs say
                                 * 22 on some boards - verify wiring!)       */

    /* Timing */
    unsigned int reset_settle_ms; /* settle delay after each VEN/DWL change  */
} pn7160_config;

/* Returns a config populated with the Raspberry Pi 5 + Elechouse defaults. */
pn7160_config pn7160_config_default(void);

#ifdef __cplusplus
}
#endif

#endif /* PN7160_CONFIG_H */
