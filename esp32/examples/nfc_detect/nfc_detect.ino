// SPDX-License-Identifier: Apache-2.0
//
// nfc_detect - ESP32 port of apps/nfc-detect.c
// Powers up the PN7160 over I2C and prints the UID of any tag presented.
// The smallest end-to-end check that wiring + library are working.
//
// Wiring: set the pins below to match your board. SDA/SCL go to Wire.begin();
// VEN/IRQ/DWL are GPIOs (IRQ is an input; an input-only pin like 34 is fine).

#include <Wire.h>
#include <nci/nci.h>

#define PIN_SDA      21     // I2C data
#define PIN_SCL      22     // I2C clock
#define PIN_VEN      25     // PN7160 VEN / reset   (output)
#define PIN_IRQ      34     // PN7160 IRQ / data-ready (input; 34 is input-only-OK)
#define PIN_DWL      27     // PN7160 DWL boot pin  (output)
#define PN7160_ADDR  0x28   // PN7160 default I2C address

static nci *dev = nullptr;

void setup() {
  Serial.begin(115200);
  delay(300);

  Wire.setBufferSize(320);          // BEFORE begin: room for full NCI packets (up to 258 B)
  Wire.begin(PIN_SDA, PIN_SCL);
  Wire.setClock(400000);

  nci_config cfg = nci_config_default();
  cfg.i2c_addr   = PN7160_ADDR;
  cfg.gpio_chip  = nullptr;         // ESP32: use the pins below directly
  cfg.ven_offset = PIN_VEN;
  cfg.irq_offset = PIN_IRQ;
  cfg.dwl_offset = PIN_DWL;

  // NCI_LOG=4 equivalent: uncomment for NCI frame tracing on Serial.
  // nci_set_log_level(NCI_LOG_NCI);

  dev = nci_open(nullptr, &cfg);    // nullptr chipset = default ("pn7160")
  if (!dev) {
    Serial.println("nci_open failed - check wiring, pins, and I2C address");
    return;
  }
  Serial.printf("up: %s\n", nci_device_info(dev));

  int r = nci_start_discovery(dev, NCI_TECH_ALL);
  if (r != NCI_OK) {
    Serial.printf("start_discovery: %s\n", nci_strerror(r));
    nci_close(dev); dev = nullptr; return;
  }
  Serial.println("present a tag (NFC-A/B/F/V)...");
}

void loop() {
  if (!dev) { delay(1000); return; }

  nci_tag tag;
  int r = nci_poll(dev, &tag, 500);
  if (r == NCI_POLL_TAG) {
    Serial.printf("TAG  %-14s uid=", nci_protocol_name(tag.protocol));
    for (int i = 0; i < tag.uid_len; i++) Serial.printf("%02X", tag.uid[i]);
    Serial.printf("  (%u bytes)%s\n", tag.uid_len, tag.more ? "  [+more]" : "");
    nci_resume_discovery(dev);
  } else if (r < 0) {
    Serial.printf("poll: %s\n", nci_strerror(r));
    delay(500);
  }
}
