// SPDX-License-Identifier: Apache-2.0
//
// nfc_detect_spi - single-core ESP32-C6 + PN7161 over SPI bring-up.
// Powers up the PN7161 over SPI and prints the UID of any tag presented.
// The smallest end-to-end check that the SPI wiring + libnci SPI backend work.
//
// Wiring (this rig - MakerGO ESP32-C6 SuperMini, strap pins GPIO4/5/8/9/15 left free):
//   PN7161      C6 GPIO   note
//   MISO    ->  2         native FSPIQ (IOMUX)
//   DWL_REQ ->  0         firmware-download boot pin (output)
//   IRQ     ->  1         data-ready input (chip-driven, verified: asserts with data)
//   NSS/CS  ->  3         manually-driven chip-select
//   SCK     ->  6         native FSPICLK
//   MOSI    ->  7         native FSPID
//   VEN     ->  18        reset/enable (output)
//   VDD -> 3V3, VANT -> 5V (RF supply, PMU CFG2), GND -> GND

#include <libnci.h>   // umbrella: attaches the libnci lib (SPI backend, NCI core)

#define PIN_SCK   6
#define PIN_MISO  2
#define PIN_MOSI  7
#define PIN_CS    3
#define PIN_VEN   18
#define PIN_IRQ   1
#define PIN_DWL   0
#define SPI_HZ    1000000    // 1 MHz: reads need to clock fast enough to catch the data window

// nci_esp32_spi_set_pins() is declared by <libnci.h> (nci/esp32.h); it selects the
// FSPI pins + manual CS the SPI backend (esp32/src/spi_esp32.cpp) drives.

static nci *dev = nullptr;
static char g_status[80] = "booting";

void setup() {
  Serial.begin(115200);
  delay(400);
  Serial.println("\n== nfc_detect_spi: PN7161 over SPI ==");
  // Wait for the host to attach the serial monitor BEFORE touching the NFCC, so the single
  // bring-up happens on a freshly-powered controller with the monitor already capturing.
  // (This board's controller only fully resets on a cold power cycle, so we get exactly one
  // clean bring-up per power-on to observe.)
  { uint32_t t0 = millis(); while (!Serial && millis() - t0 < 8000) delay(10); }
  delay(800);
  Serial.println("== attached; bringing up NFCC now ==");

  nci_esp32_spi_set_pins(PIN_SCK, PIN_MISO, PIN_MOSI, PIN_CS);

  nci_config cfg = nci_config_default();
  cfg.bus_type     = NCI_BUS_SPI;
  cfg.spi_speed_hz = SPI_HZ;
  cfg.gpio_chip    = nullptr;               // ESP32: use the pins below directly
  cfg.ven_offset   = PIN_VEN;
  cfg.irq_offset   = PIN_IRQ;
  cfg.dwl_offset   = PIN_DWL;

  nci_set_log_level(NCI_LOG_NCI);           // trace NCI frames on Serial during bring-up

  dev = nci_open(nullptr, &cfg);            // nullptr chipset = default ("pn7160", covers PN7161)
  if (!dev) {
    snprintf(g_status, sizeof g_status, "nci_open FAILED");
    Serial.println(g_status);
    return;
  }
  snprintf(g_status, sizeof g_status, "UP: %s", nci_device_info(dev));
  Serial.println(g_status);

  int r = nci_start_discovery(dev, NCI_TECH_ALL);
  if (r != NCI_OK) {
    snprintf(g_status, sizeof g_status, "UP but start_discovery: %s", nci_strerror(r));
    nci_close(dev); dev = nullptr;
  }
}

void loop() {
  static uint32_t last = 0;
  if (millis() - last >= 2000) { last = millis(); Serial.printf("[status] %s\n", g_status); }  // reprint so a late attach still sees it
  if (!dev) { delay(50); return; }
  nci_tag tag;
  int r = nci_poll(dev, &tag, 300);
  if (r == NCI_POLL_TAG) {
    Serial.printf("TAG  proto=%s  uid=", nci_protocol_name(tag.protocol));
    for (int i = 0; i < tag.uid_len; i++) Serial.printf("%02X", tag.uid[i]);
    Serial.println();
    nci_resume_discovery(dev);
  } else if (r < 0) {
    Serial.printf("poll: %s\n", nci_strerror(r));
    delay(200);
  }
}
