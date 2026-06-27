/* SPDX-License-Identifier: Apache-2.0 */
/*
 * apdu.h - The seam between the card-application layers (T4T NDEF, DESFire)
 * and whatever moves bytes to the card.
 *
 * Higher layers depend only on this function pointer, not on nci or the
 * NFCC. The façade plugs in nci_transceive; a unit test plugs in a mock
 * that returns scripted APDU responses. Same trick as the transport vtable.
 *
 *   return 0 on success (with *rx_len set), <0 on error.
 */
#ifndef NCI_APDU_H
#define NCI_APDU_H

#include <stddef.h>
#include <stdint.h>

typedef int (*apdu_fn)(void *ctx,
                       const uint8_t *tx, size_t tx_len,
                       uint8_t *rx, size_t rx_cap, size_t *rx_len);

#endif /* NCI_APDU_H */
