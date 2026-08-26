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
 * Runs after CORE_INIT and before RF_DISCOVER_MAP (device.c). Pushes the
 * discovery-period tuning that suits the PN7160's battery-powered role via a
 * standard NCI CORE_SET_CONFIG. The one parameter written here - TOTAL_DURATION
 * (config ID 0x00, 2 octets, ms, little-endian) - is a spec-stable NCI config
 * value, so it is real on both NCI 1.0 and 2.0 silicon.
 *
 * A longer discovery period on the battery unit means the RF field ramps and
 * restarts less often between poll loops (lower average current) at the cost of
 * a slightly slower worst-case tag pickup - the opposite trade from the
 * mains-powered PN7150. The value is illustrative and meant to be tuned on the
 * bench; it is NOT yet hardware-validated here.
 *
 * NOT DONE (needs the NXP reference config from UM11495): the proprietary RF
 * tuning - guard time, listen duration, per-technology retries and analog RF
 * params - which NXP delivers as vendor-specific config IDs (and the proprietary
 * RF_SET_CONFIG). Those IDs are not fabricated here; the extension point is this
 * function, and additional params append to the CORE_SET_CONFIG TLV list below. */
static int nci_configure(nci_transport *t, const nci_dev_info *info)
{
    if (!t) return NCI_E_INVAL;

    /* CORE_SET_CONFIG: 1 param, TOTAL_DURATION = 1000 ms (0x03E8, little-endian).
     *   20 02 <len> <num> <id> <len> <val...>  */
    static const uint8_t set_cfg[] = {
        0x20, 0x02, 0x05, 0x01, 0x00, 0x02, 0xE8, 0x03,
    };
    uint8_t rsp[64];
    size_t  rlen = 0;
    int rc = nci_chip_command(t, set_cfg, sizeof set_cfg, rsp, sizeof rsp, &rlen);
    if (rc != NCI_OK) {
        LOGE("pn7160: CORE_SET_CONFIG failed (%d)", rc);
        return rc;
    }
    if (rlen < 4 || rsp[3] != 0x00) {                  /* status octet */
        LOGE("pn7160: CORE_SET_CONFIG status 0x%02x", rlen >= 4 ? rsp[3] : 0xFF);
        return NCI_E_STATUS;
    }
    LOGD("pn7160: configure ok (nci_ver 0x%02x) - discovery period tuned",
         info ? info->nci_version : 0);
    return NCI_OK;
}

const nci_chip nci_chip_pn7160 = {
    .info = {
        .name             = "pn7160",
        .description      = "NXP PN7160/PN7161 NCI 2.0 NFC controller",
        .default_i2c_addr = 0x28,
        .caps             = NCI_CAP_ISO_DEP | NCI_CAP_NFC_DEP |
                            NCI_CAP_CE | NCI_CAP_FW_UPDATE,
    },
    .transport_open = nci_transport_open,
    .configure      = nci_configure,
};
