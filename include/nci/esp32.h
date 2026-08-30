/* SPDX-License-Identifier: Apache-2.0 */
/*
 * nci/esp32.h - ESP32 Arduino build: SPI pin selection (public entry point).
 *
 * The ESP32 SPI byte-pipe (esp32/src/spi_esp32.cpp) drives the PN7160/PN7161 over
 * the Arduino SPIClass. A sketch chooses the four bus pins + manual chip-select
 * BEFORE nci_open(); nci_open() then brings the controller up on SPI whenever
 * nci_config.bus_type == NCI_BUS_SPI (I2C rigs leave bus_type at its default and
 * never call this). This is the ONE ESP32-specific call a sketch needs - so it
 * lives in a public header instead of an ad-hoc `extern` in every sketch.
 *
 * No definition exists on the Linux (spidev) build, which selects SPI pins through
 * nci_config / the device node instead; the declaration is harmless there.
 */
#ifndef NCI_ESP32_H
#define NCI_ESP32_H

#ifdef __cplusplus
extern "C" {
#endif

/* Select the SPI bus pins the ESP32 SPI backend uses. Call once before nci_open().
 * Example (MakerGO ESP32-C6): nci_esp32_spi_set_pins(6, 2, 7, 3). */
void nci_esp32_spi_set_pins(int sck, int miso, int mosi, int cs);

#ifdef __cplusplus
}
#endif

#endif /* NCI_ESP32_H */
