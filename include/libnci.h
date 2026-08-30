/* SPDX-License-Identifier: Apache-2.0 */
/*
 * libnci.h - top-level umbrella header.
 *
 * Convenience single-include that pulls in the public libnci surface, and - on
 * the ESP32 Arduino build - the discovery entry point: the Arduino library
 * resolver keys on a header at the include-path ROOT, and every other public
 * libnci header lives under <nci/...>, so a sketch begins with
 *
 *     #include <libnci.h>
 *
 * to make the library (and its bundled sources: the NCI stack + kdf.c + the
 * mbedTLS crypto backend) get compiled and linked. After this include the
 * individual <nci/...> headers resolve directly too.
 */
#ifndef LIBNCI_UMBRELLA_H
#define LIBNCI_UMBRELLA_H

#include <nci/nci.h>
#include <nci/kdf.h>
#include <nci/p2p.h>
#include <nci/esp32.h>   /* nci_esp32_spi_set_pins (SPI rig pin selection) */

#endif /* LIBNCI_UMBRELLA_H */
