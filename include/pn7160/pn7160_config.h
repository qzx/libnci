/* SPDX-License-Identifier: Apache-2.0 */
/*
 * pn7160_config.h - Compatibility shim.
 *
 * The configuration struct is now the chipset-neutral hci_config
 * (include/hcinfc/config.h). pn7160_config remains as an alias so existing
 * code keeps compiling. New code should use hci_config / hci_config_default().
 */
#ifndef PN7160_CONFIG_H
#define PN7160_CONFIG_H

#include "hcinfc/config.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef hci_config pn7160_config;

/* Pi 5 + Elechouse PN7160 defaults (== hci_config_default()). */
pn7160_config pn7160_config_default(void);

#ifdef __cplusplus
}
#endif

#endif /* PN7160_CONFIG_H */
