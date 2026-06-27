/* SPDX-License-Identifier: Apache-2.0 */
/* log.c - shared log-level state + the leveled hex dumper (see log.h). */
#include "log.h"

static int g_level = -1;   /* <0 = unresolved */

static int resolve_env(void)
{
    const char *l = getenv("NCI_LOG");
    if (l && *l) {
        int v = atoi(l);
        return v < PN7160_LOG_SILENT ? PN7160_LOG_SILENT
             : v > PN7160_LOG_BYTES  ? PN7160_LOG_BYTES : v;
    }
    const char *d = getenv("NCI_DEBUG");
    if (!d || !*d) d = getenv("PN7160_DEBUG");      /* legacy name */
    if (d && *d && *d != '0') return PN7160_LOG_NCI; /* old boolean -> frames */
    return PN7160_LOG_ERROR;
}

int pn7160_log_level(void)
{
    if (g_level < 0) g_level = resolve_env();
    return g_level;
}

void pn7160_log_set_level(int level)
{
    g_level = level < PN7160_LOG_SILENT ? PN7160_LOG_SILENT
            : level > PN7160_LOG_BYTES  ? PN7160_LOG_BYTES : level;
}

void pn7160_log_hex_at(int level, const char *tag, const uint8_t *buf, size_t len)
{
    if (pn7160_log_level() < level) return;
    fprintf(stderr, "[nci] %s (%zu):", tag, len);
    for (size_t i = 0; i < len; i++)
        fprintf(stderr, " %02x", buf[i]);
    fprintf(stderr, "\n");
}
