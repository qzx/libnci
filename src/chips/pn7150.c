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

/* Post-init configuration hook (impl.txt #122 RF parameter tuning). Runs after
 * CORE_INIT and before RF_DISCOVER_MAP.
 *
 * Same standard NCI CORE_SET_CONFIG path as the PN7160, but tuned for the
 * PN7150's mains-/bus-powered role: a SHORTER TOTAL_DURATION (config ID 0x00,
 * 2 octets, ms, little-endian) restarts the discovery loop more often for
 * snappier tag pickup - current draw is not the constraint here. TOTAL_DURATION
 * is a spec-stable NCI config value and works on the PN7150's NCI 1.0 core.
 * The value is illustrative/tunable and is NOT hardware-validated here.
 *
 * NOT DONE (needs the NXP reference config): proprietary RF analog tuning /
 * retries via vendor-specific config IDs - not fabricated; they append to the
 * TLV list below when the UM11495 values are on hand. */
static int pn7150_configure(nci_transport *t, const nci_dev_info *info)
{
    if (!t) return NCI_E_INVAL;

    /* CORE_SET_CONFIG: 1 param, TOTAL_DURATION = 500 ms (0x01F4, little-endian). */
    static const uint8_t set_cfg[] = {
        0x20, 0x02, 0x05, 0x01, 0x00, 0x02, 0xF4, 0x01,
    };
    uint8_t rsp[64];
    size_t  rlen = 0;
    int rc = nci_chip_command(t, set_cfg, sizeof set_cfg, rsp, sizeof rsp, &rlen);
    if (rc != NCI_OK) {
        LOGE("pn7150: CORE_SET_CONFIG failed (%d)", rc);
        return rc;
    }
    if (rlen < 4 || rsp[3] != 0x00) {                  /* status octet */
        LOGE("pn7150: CORE_SET_CONFIG status 0x%02x", rlen >= 4 ? rsp[3] : 0xFF);
        return NCI_E_STATUS;
    }
    LOGD("pn7150: configure ok (nci_ver 0x%02x) - discovery period tuned",
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
