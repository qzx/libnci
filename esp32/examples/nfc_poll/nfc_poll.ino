// SPDX-License-Identifier: Apache-2.0
//
// nfc_poll - ESP32 port of apps/nfc-poll.c
// Like nfc_detect, but also cycles through multiple tags in the field at once.

#include <Wire.h>
#include <libnci.h>   // umbrella: attaches the libnci library, then <nci/...> resolves

#define PIN_SDA      21
#define PIN_SCL      22
#define PIN_VEN      25
#define PIN_IRQ      34
#define PIN_DWL      27
#define PN7160_ADDR  0x28

static nci *dev = nullptr;

static void print_tag(const nci_tag *t) {
  Serial.printf("TAG  %-14s uid=", nci_protocol_name(t->protocol));
  if (t->uid_len == 0) Serial.print("(none)");
  else for (int i = 0; i < t->uid_len; i++) Serial.printf("%02X", t->uid[i]);
  Serial.printf("  (%u bytes)%s\n", t->uid_len, t->more ? "  [+more in field]" : "");
}

void setup() {
  Serial.begin(115200);
  delay(300);

  Wire.setBufferSize(320);
  Wire.begin(PIN_SDA, PIN_SCL);
  Wire.setClock(400000);

  nci_config cfg = nci_config_default();
  cfg.i2c_addr   = PN7160_ADDR;
  cfg.gpio_chip  = nullptr;
  cfg.ven_offset = PIN_VEN;
  cfg.irq_offset = PIN_IRQ;
  cfg.dwl_offset = PIN_DWL;

  dev = nci_open(nullptr, &cfg);
  if (!dev) { Serial.println("nci_open failed - check wiring/pins/address"); return; }
  Serial.printf("up: %s\n", nci_device_info(dev));

  // Poll a subset with e.g. NCI_TECH_A | NCI_TECH_B; here we poll everything.
  int r = nci_start_discovery(dev, NCI_TECH_ALL);
  if (r != NCI_OK) { Serial.printf("start_discovery: %s\n", nci_strerror(r));
                     nci_close(dev); dev = nullptr; return; }
  Serial.println("polling - present a tag...");
}

void loop() {
  if (!dev) { delay(1000); return; }

  nci_tag tag;
  int r = nci_poll(dev, &tag, 500);
  if (r == NCI_POLL_TAG) {
    print_tag(&tag);
    while (tag.more) {                       // several tags share the field
      if (nci_select_next_tag(dev, &tag) != NCI_OK) break;
      print_tag(&tag);
    }
    nci_resume_discovery(dev);
  } else if (r < 0) {
    Serial.printf("poll: %s\n", nci_strerror(r));
    delay(500);
  }
}
