/* SPDX-License-Identifier: Apache-2.0 */
/*
 * chipset.h - Internal chipset driver interface.
 *
 * A "chipset" is one NFC controller family (PN7160, and later PN7150, PN5180,
 * ...). Each provides a small ops table: its public info, and the hooks that
 * differ between controllers. Everything generic (CORE_RESET/INIT, discovery,
 * ISO-DEP transceive) lives in the shared NCI layer and is reused unchanged.
 *
 * To add a controller: create src/chips/<chip>.c defining a `const hci_chip`,
 * declare it extern here, and list it in chipset.c's registry. No public
 * header changes.
 */
#ifndef HCINFC_CHIPSET_H
#define HCINFC_CHIPSET_H

#include "hcinfc/hcinfc.h"
#include "transport.h"
#include "nci.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct hci_chip {
    hci_chipset_info info;

    /* Open the byte transport for this controller from cfg. Most chips share
     * the I2C/SPI + libgpiod transport (pn7160_transport_open); a chip with a
     * different bus would supply its own. */
    pn7160_transport *(*transport_open)(const hci_config *cfg);

    /* Chipset-specific configuration pushed after CORE_RESET + CORE_INIT and
     * before RF_DISCOVER_MAP (e.g. proprietary CORE_SET_CONFIG, RF tuning).
     * May be NULL. Returns HCI_OK or a negative hci_status. */
    int (*configure)(pn7160_transport *t, const nci_device_info *info);
} hci_chip;

/* Registry access (defined in chipset.c). */
const hci_chip *hci_chip_find(const char *name);   /* NULL => default chip   */
const hci_chip *hci_chip_at(size_t index);
size_t          hci_chip_count(void);

/* Compiled-in chipset drivers. */
extern const hci_chip hci_chip_pn7160;

#ifdef __cplusplus
}
#endif

#endif /* HCINFC_CHIPSET_H */
