// SPDX-License-Identifier: Apache-2.0
//
// nfc_read_ndef - ESP32 port of apps/nfc-read-ndef.c
// Reads the NDEF message from a Type 4 tag (NTAG 424 DNA, DESFire-with-NDEF,
// ...) and decodes the first record (Text / URI).

#include <Wire.h>
#include <libnci.h>   // umbrella: attaches the libnci library, then <nci/...> resolves
#include <nci/ndef.h>

#define PIN_SDA      21
#define PIN_SCL      22
#define PIN_VEN      25
#define PIN_IRQ      34
#define PIN_DWL      27
#define PN7160_ADDR  0x28

static nci *dev = nullptr;

static void show_ndef(const uint8_t *msg, size_t len) {
  Serial.printf("NDEF message (%u bytes): ", (unsigned)len);
  for (size_t i = 0; i < len; i++) Serial.printf("%02X", msg[i]);
  Serial.println();

  ndef_record rec;
  if (ndef_first_record(msg, len, &rec) != 0) { Serial.println("(parse failed)"); return; }
  Serial.printf("record: TNF=0x%02x type=\"%.*s\" payload=%u bytes\n",
                rec.tnf, rec.type_len, rec.type, (unsigned)rec.payload_len);

  char text[256], lang[8];
  if (ndef_is_text(&rec) && ndef_get_text(&rec, text, sizeof text, lang, sizeof lang) >= 0)
    Serial.printf("  TEXT [%s]: %s\n", lang, text);
  else if (ndef_is_uri(&rec) && ndef_get_uri(&rec, text, sizeof text) >= 0)
    Serial.printf("  URI: %s\n", text);
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

  if (nci_start_discovery(dev, NCI_TECH_ALL) != NCI_OK) {
    Serial.println("start_discovery failed"); nci_close(dev); dev = nullptr; return;
  }
  Serial.println("present a Type 4 NDEF tag...");
}

void loop() {
  if (!dev) { delay(1000); return; }

  nci_tag tag;
  int r = nci_poll(dev, &tag, 500);
  if (r != NCI_POLL_TAG) { if (r < 0) delay(500); return; }

  Serial.printf("\n--- tag: %s, uid=", nci_protocol_name(tag.protocol));
  for (int i = 0; i < tag.uid_len; i++) Serial.printf("%02X", tag.uid[i]);
  Serial.println(" ---");

  if (!nci_tag_supports_apdu(dev)) {
    Serial.println("not an ISO-DEP tag; no NDEF read");
  } else {
    uint8_t ndef[1024]; size_t n = 0;
    if (nci_read_ndef(dev, ndef, sizeof ndef, &n) == NCI_OK) show_ndef(ndef, n);
    else Serial.println("no readable NDEF (needs auth, or not a Type 4 tag)");
  }
  nci_resume_discovery(dev);
}
