/* SPDX-License-Identifier: Apache-2.0 */
/*
 * chipset.c - The chipset driver registry.
 *
 * One flat table of compiled-in controllers. The first entry is the default
 * used when nci_open() is called with a NULL chipset name.
 */
#include "chipset.h"
#include <string.h>

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
