/* SPDX-License-Identifier: Apache-2.0 */
/*
 * config.h - Runtime configuration for libnci.
 *
 * Everything the old NXP code baked in as #defines (pins, bus, address) lives
 * here as data, injected at nci_open(). Changing a pin or moving between a
 * Pi 4 and a Pi 5 is a config change, never a recompile.
 *
 * The struct is shared across chipsets; chipset-specific defaults (e.g. the
 * PN7160's 0x28 I2C address) come from the chipset registry, applied by
 * nci_open() when a field is left at its zero/unset value.
 */
#ifndef NCI_CONFIG_H
#define NCI_CONFIG_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Byte transport selection (impl.txt #117: SPI alongside I2C). */
typedef enum {
    NCI_BUS_I2C = 0,   /* default */
    NCI_BUS_SPI = 1,
} nci_bus_type;

typedef struct {
    /* Byte bus */
    int          bus_type;      /* nci_bus_type; 0 = I2C (default)           */
    const char  *i2c_bus;       /* e.g. "/dev/i2c-1" (also the SPI dev path) */
    uint16_t     i2c_addr;      /* 7-bit slave address; 0 => chipset default */
    uint32_t     spi_speed_hz;  /* SPI clock when bus_type == NCI_BUS_SPI    */

    /* GPIO (libgpiod v2). If gpio_chip is NULL/"", the chip is auto-detected
     * by controller label (pinctrl-rp1 on Pi 5, pinctrl-bcm* on Pi 4). */
    const char  *gpio_chip;     /* e.g. "/dev/gpiochip4" (Pi 5 RP1)          */
    unsigned int ven_offset;    /* VEN / reset            (BCM 24)           */
    unsigned int irq_offset;    /* IRQ / data-ready input (BCM 23)           */
    unsigned int dwl_offset;    /* DWL_REQ firmware boot  (BCM 25)           */

    /* Timing */
    unsigned int reset_settle_ms; /* settle delay after each VEN/DWL change  */
} nci_config;

/* Config populated with the Raspberry Pi 5 + Elechouse PN7160 defaults. */
nci_config nci_config_default(void);

#ifdef __cplusplus
}
#endif

#endif /* NCI_CONFIG_H */
