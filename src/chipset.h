/* SPDX-License-Identifier: Apache-2.0 */
/*
 * chipset.h - Internal chipset driver interface.
 *
 * A "chipset" is one NFC controller family (PN7160, and later PN7150, PN5180,
 * ...). Each provides a small ops table: its public info, and the hooks that
 * differ between controllers. Everything generic (CORE_RESET/INIT, discovery,
 * ISO-DEP transceive) lives in the shared NCI layer and is reused unchanged.
 *
 * To add a controller: create src/chips/<chip>.c defining a `const nci_chip`,
 * declare it extern here, and list it in chipset.c's registry. No public
 * header changes.
 */
#ifndef NCI_CHIPSET_H
#define NCI_CHIPSET_H

#include "nci/nci.h"
#include "transport.h"
#include "nci.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct nci_chip {
    nci_chipset_info info;

    /* Open the byte transport for this controller from cfg. Most chips share
     * the I2C/SPI + libgpiod transport (nci_transport_open); a chip with a
     * different bus would supply its own. */
    nci_transport *(*transport_open)(const nci_config *cfg);

    /* Chipset-specific configuration pushed after CORE_RESET + CORE_INIT and
     * before RF_DISCOVER_MAP (e.g. proprietary CORE_SET_CONFIG, RF tuning).
     * May be NULL. Returns NCI_OK or a negative nci_status. */
    int (*configure)(nci_transport *t, const nci_dev_info *info);
} nci_chip;

/* Send one NCI command over the transport and wait for its matching RSP,
 * skipping any notifications that arrive first. On success returns NCI_OK and
 * (if rsp_len non-NULL) the RSP length; the RSP is copied into rsp[0..rsp_cap).
 * A small self-contained helper so chipset configure hooks can push their own
 * CORE_SET_CONFIG without reaching into nci.c's private command(). */
int nci_chip_command(nci_transport *t,
                     const uint8_t *cmd, size_t cmd_len,
                     uint8_t *rsp, size_t rsp_cap, size_t *rsp_len);

/* Registry access (defined in chipset.c). */
const nci_chip *nci_chip_find(const char *name);   /* NULL => default chip   */
const nci_chip *nci_chip_at(size_t index);
size_t          nci_chip_count(void);

/* Compiled-in chipset drivers. */
extern const nci_chip nci_chip_pn7160;   /* NCI 2.0 */
extern const nci_chip nci_chip_pn7150;   /* NCI 1.0 */

#ifdef __cplusplus
}
#endif

#endif /* NCI_CHIPSET_H */
