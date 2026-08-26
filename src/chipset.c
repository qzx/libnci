/* SPDX-License-Identifier: Apache-2.0 */
/*
 * chipset.c - The chipset driver registry.
 *
 * One flat table of compiled-in controllers. The first entry is the default
 * used when nci_open() is called with a NULL chipset name.
 */
#include "chipset.h"
#include "log.h"
#include <string.h>

/* ---- shared NCI command helper (see chipset.h) ------------------------- *
 * Mirrors the private command() in nci.c: write the command, then read packets
 * until the matching RSP (same GID/OID) appears, discarding notifications in
 * between. Kept minimal - configure hooks send a couple of CORE_SET_CONFIGs. */
#define CHIP_HDR_LEN 3
#define CHIP_MT_RSP  0x40   /* Message Type = Response, in the top bits of byte 0 */

int nci_chip_command(nci_transport *t,
                     const uint8_t *cmd, size_t cmd_len,
                     uint8_t *rsp, size_t rsp_cap, size_t *rsp_len)
{
    if (!t || !cmd || cmd_len < CHIP_HDR_LEN || !rsp || rsp_cap < CHIP_HDR_LEN)
        return NCI_E_INVAL;
    if (t->write(t->ctx, cmd, cmd_len) < 0)
        return NCI_E_IO;

    const uint8_t want_gid = cmd[0] & 0x0F;
    const uint8_t want_oid = cmd[1];
    for (int tries = 0; tries < 8; tries++) {
        int n = t->read(t->ctx, rsp, rsp_cap, 1000);
        if (n < CHIP_HDR_LEN) {
            LOGE("chip: no/short response to cmd %02x%02x", cmd[0], cmd[1]);
            return NCI_E_IO;
        }
        if ((rsp[0] & 0xE0) == CHIP_MT_RSP &&
            (rsp[0] & 0x0F) == want_gid && rsp[1] == want_oid) {
            t->last_nci_status = (n > CHIP_HDR_LEN) ? rsp[CHIP_HDR_LEN] : 0x00;
            if (rsp_len) *rsp_len = (size_t)n;
            return NCI_OK;
        }
        LOGD("chip: skipping unsolicited %02x%02x while awaiting rsp", rsp[0], rsp[1]);
    }
    LOGE("chip: gave up waiting for rsp to %02x%02x", cmd[0], cmd[1]);
    return NCI_E_PROTO;
}

static const nci_chip *const registry[] = {
    &nci_chip_pn7160,   /* default (NCI 2.0) */
    &nci_chip_pn7150,   /* NCI 1.0 */
    /* Future controllers slot in here, e.g.:
     *   &nci_chip_pn5180,
     */
};

#define N_CHIPS (sizeof registry / sizeof registry[0])

size_t nci_chip_count(void) { return N_CHIPS; }

const nci_chip *nci_chip_at(size_t index)
{
    return index < N_CHIPS ? registry[index] : NULL;
}

const nci_chip *nci_chip_find(const char *name)
{
    if (!name || !*name) return registry[0];   /* default */
    for (size_t i = 0; i < N_CHIPS; i++)
        if (strcmp(registry[i]->info.name, name) == 0)
            return registry[i];
    return NULL;
}

/* ---- public chipset enumeration (nci/nci.h) ---------------------------- */
size_t nci_chipset_count(void) { return N_CHIPS; }

const nci_chipset_info *nci_chipset_get(size_t index)
{
    const nci_chip *c = nci_chip_at(index);
    return c ? &c->info : NULL;
}

const nci_chipset_info *nci_chipset_find(const char *name)
{
    const nci_chip *c = nci_chip_find(name);
    return c ? &c->info : NULL;
}
