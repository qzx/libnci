/* SPDX-License-Identifier: Apache-2.0 */
/*
 * chips/pn7150.c - NXP PN7150 chipset driver.
 *
 * The PN7150 is a full NCI 1.0 controller. The shared NCI layer already handles
 * the version difference: CORE_RESET carries the version inline on 1.0 (no
 * CORE_RESET_NTF), and nci_core_init() sends the 3-byte NCI 1.0 CORE_INIT form
 * and parses the Manufacturer ID/Info out of CORE_INIT_RSP when nci_version <
 * 0x20. So this entry supplies only the part-specific bits: name, default I2C
 * address (0x28 - same as the PN7160), the shared I2C + libgpiod transport, and
 * a hook for RF tuning.
 *
 * Functionally it is a drop-in for reading DESFire / ISO-DEP cards; versus the
 * PN7160 it has lower RF output power / range, ~150 uA (vs ~100 uA) low-power
 * polling, and no SPI option - which is why the PN7150 suits a bus-/mains-
 * powered reader while the PN7160 goes in the battery-powered unit.
 */
#include "chipset.h"
#include "log.h"

/* Post-init configuration hook. Deliberate no-op: the stock NCI bring-up polls
 * all technologies with sane defaults (validated on the PN7160, same NCI RF
 * config path). PN7150-specific CORE_SET_CONFIG / RF tuning would land here. */
static int pn7150_configure(nci_transport *t, const nci_dev_info *info)
{
    (void)t;
    LOGD("nci: configure pn7150 (nci_ver 0x%02x) - using NCI defaults",
         info ? info->nci_version : 0);
    return NCI_OK;
}

const nci_chip nci_chip_pn7150 = {
    .info = {
        .name             = "pn7150",
        .description      = "NXP PN7150 NCI 1.0 NFC controller",
        .default_i2c_addr = 0x28,
        .caps             = NCI_CAP_ISO_DEP | NCI_CAP_NFC_DEP |
                            NCI_CAP_CE | NCI_CAP_FW_UPDATE,
    },
    .transport_open = nci_transport_open,
    .configure      = pn7150_configure,
};
