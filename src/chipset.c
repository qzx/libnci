/* SPDX-License-Identifier: Apache-2.0 */
/*
 * chipset.c - The chipset driver registry.
 *
 * One flat table of compiled-in controllers. The first entry is the default
 * used when hci_open() is called with a NULL chipset name.
 */
#include "chipset.h"
#include <string.h>

static const hci_chip *const registry[] = {
    &hci_chip_pn7160,
    /* Future controllers slot in here, e.g.:
     *   &hci_chip_pn7150,
     *   &hci_chip_pn5180,
     */
};

#define N_CHIPS (sizeof registry / sizeof registry[0])

size_t hci_chip_count(void) { return N_CHIPS; }

const hci_chip *hci_chip_at(size_t index)
{
    return index < N_CHIPS ? registry[index] : NULL;
}

const hci_chip *hci_chip_find(const char *name)
{
    if (!name || !*name) return registry[0];   /* default */
    for (size_t i = 0; i < N_CHIPS; i++)
        if (strcmp(registry[i]->info.name, name) == 0)
            return registry[i];
    return NULL;
}

/* ---- public chipset enumeration (hcinfc.h) ---------------------------- */
size_t hci_chipset_count(void) { return N_CHIPS; }

const hci_chipset_info *hci_chipset_get(size_t index)
{
    const hci_chip *c = hci_chip_at(index);
    return c ? &c->info : NULL;
}

const hci_chipset_info *hci_chipset_find(const char *name)
{
    const hci_chip *c = hci_chip_find(name);
    return c ? &c->info : NULL;
}
