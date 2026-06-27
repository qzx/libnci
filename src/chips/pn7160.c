/* SPDX-License-Identifier: Apache-2.0 */
/*
 * chips/pn7160.c - NXP PN7160 / PN7161 chipset driver.
 *
 * The PN7160 is a full NCI 2.0 controller, so the heavy lifting (CORE_RESET /
 * CORE_INIT / RF_DISCOVER) is the shared NCI layer. This entry supplies only
 * what is specific to the part: its name, default I2C address (0x28), the
 * shared I2C + libgpiod transport, and a place to hang chipset-specific RF
 * configuration.
 */
#include "chipset.h"
#include "log.h"

/* Post-init configuration hook (impl.txt #122 RF parameter tuning).
 *
 * Kept a deliberate no-op for now: the stock NCI bring-up already polls all
 * four technologies with sane defaults and is what is validated on hardware.
 * Chipset-specific CORE_SET_CONFIG / proprietary tuning lands here without
 * touching the generic device layer. */
static int pn7160_configure(pn7160_transport *t, const nci_device_info *info)
{
    (void)t;
    LOGD("pn7160: configure (nci_ver 0x%02x) - using NCI defaults",
         info ? info->nci_version : 0);
    return HCI_OK;
}

const hci_chip hci_chip_pn7160 = {
    .info = {
        .name             = "pn7160",
        .description      = "NXP PN7160/PN7161 NCI 2.0 NFC controller",
        .default_i2c_addr = 0x28,
        .caps             = HCI_CAP_ISO_DEP | HCI_CAP_NFC_DEP |
                            HCI_CAP_CE | HCI_CAP_FW_UPDATE,
    },
    .transport_open = pn7160_transport_open,
    .configure      = pn7160_configure,
};
