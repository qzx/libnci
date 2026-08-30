// SPDX-License-Identifier: Apache-2.0
//
// nfc_p2p - NFC Peer-to-Peer (NFC-DEP + LLCP + SNEP) between two libnci boards.
// Flash BOTH boards with this sketch: one with USE_SPI 1 (SPI reader), one with
// USE_SPI 0 (I2C reader). Put their antennas in each other's fields. Each cycle,
// whichever board wins the initiator role SNEP-PUTs a text NDEF; the other, as
// target, receives and prints it. Roles may alternate cycle to cycle.

#define USE_SPI 1        // 1 = SPI board (PN7161 SPI), 0 = I2C board

#include <libnci.h>

#if USE_SPI
  // --- SPI board wiring (proven this rig, MakerGO C6 SuperMini) ---
  #define PIN_SCK  6
  #define PIN_MISO 2
  #define PIN_MOSI 7
  #define PIN_CS   3
  #define PIN_VEN  18
  #define PIN_IRQ  1
  #define PIN_DWL  0
  #define SPI_HZ   1000000
  extern "C" void nci_esp32_spi_set_pins(int sck, int miso, int mosi, int cs);
  static const char *WHOAMI = "spi";
#else
  #include <Wire.h>
  // --- I2C board wiring (qzxbridge C6 SuperMini defaults, QzxNfcBridge.h) ---
  #define PIN_SDA  20
  #define PIN_SCL  19
  #define PIN_VEN  18
  #define PIN_IRQ  2
  #define PIN_DWL  3
  #define PN7160_ADDR 0x28
  static const char *WHOAMI = "i2c";
#endif

static nci *dev = nullptr;

// A minimal NDEF "Text" record: "hello from <who>" (UTF-8, lang "en").
static size_t make_text_ndef(uint8_t *out, size_t cap, const char *text) {
  uint8_t lang[] = { 'e', 'n' };
  size_t  tl = strlen(text);
  size_t  payload = 1 + sizeof lang + tl;         // status + lang + text
  size_t  i = 0;
  if (cap < 4 + payload) return 0;
  out[i++] = 0xD1;                                 // MB|ME|SR, TNF=well-known
  out[i++] = 0x01;                                 // type length
  out[i++] = (uint8_t)payload;                     // payload length (SR: 1 byte)
  out[i++] = 0x54;                                 // type 'T'
  out[i++] = (uint8_t)(sizeof lang);               // status: UTF-8, lang len=2
  memcpy(out + i, lang, sizeof lang); i += sizeof lang;
  memcpy(out + i, text, tl); i += tl;
  return i;
}

static void dump_ndef(const uint8_t *b, size_t n) {
  Serial.printf("RECV %u B NDEF:", (unsigned)n);
  for (size_t i = 0; i < n; i++) Serial.printf(" %02x", b[i]);
  Serial.println();
  // if it's a Text record, print the text
  if (n >= 4 && (b[0] & 0x07) == 0x01 && b[3] == 0x54) {
    uint8_t st = b[4]; size_t ll = st & 0x3F;
    if (5 + ll <= n) {
      Serial.print("  text: \"");
      for (size_t i = 5 + ll; i < n; i++) Serial.write(b[i]);
      Serial.println("\"");
    }
  }
}

void setup() {
  Serial.begin(115200);
  { uint32_t t0 = millis(); while (!Serial && millis() - t0 < 8000) delay(10); }
  delay(600);
  Serial.printf("\n== nfc_p2p [%s] ==\n", WHOAMI);

  nci_config cfg = nci_config_default();
  cfg.ven_offset = PIN_VEN;
  cfg.irq_offset = PIN_IRQ;
  cfg.dwl_offset = PIN_DWL;
  cfg.gpio_chip  = nullptr;
#if USE_SPI
  nci_esp32_spi_set_pins(PIN_SCK, PIN_MISO, PIN_MOSI, PIN_CS);
  cfg.bus_type     = NCI_BUS_SPI;
  cfg.spi_speed_hz = SPI_HZ;
#else
  Wire.setBufferSize(320);
  Wire.begin(PIN_SDA, PIN_SCL);
  Wire.setClock(400000);
  cfg.bus_type = NCI_BUS_I2C;
  cfg.i2c_addr = PN7160_ADDR;
#endif
  nci_set_log_level(NCI_LOG_NCI);

  dev = nci_open(nullptr, &cfg);
  if (!dev) { Serial.println("nci_open FAILED"); return; }
  Serial.printf("UP: %s\n", nci_device_info(dev));

  int r = nci_p2p_start(dev);
  Serial.printf("p2p_start: %s\n", r == NCI_OK ? "ok" : nci_strerror(r));
  if (r != NCI_OK) { nci_close(dev); dev = nullptr; }
}

void loop() {
  static uint32_t last = 0;
  if (millis() - last >= 3000) {
    last = millis();
    Serial.printf("[%s] %s, waiting for a peer...\n", WHOAMI, dev ? "P2P armed" : "DOWN");
  }
  if (!dev) { delay(500); return; }
  nci_tag tag;
  int r = nci_poll(dev, &tag, 500);
  if (r != NCI_POLL_TAG) { if (r < 0) delay(200); return; }
  if (tag.protocol != NCI_PROTO_NFCDEP) {          // a plain tag wandered in
    Serial.printf("(non-P2P tag proto=%s)\n", nci_protocol_name(tag.protocol));
    nci_resume_discovery(dev);
    return;
  }

  if (nci_p2p_is_target(dev)) {
    Serial.println("P2P: TARGET - waiting for SNEP PUT...");
    uint8_t buf[512]; size_t n = 0;
    int s = nci_snep_serve(dev, buf, sizeof buf, &n, 8000);
    if (s == NCI_OK) dump_ndef(buf, n);
    else Serial.printf("snep_serve: %s\n", nci_strerror(s));
  } else {
    Serial.println("P2P: INITIATOR - sending SNEP PUT...");
    char msg[48]; snprintf(msg, sizeof msg, "hello from %s", WHOAMI);
    uint8_t ndef[64];
    size_t nl = make_text_ndef(ndef, sizeof ndef, msg);
    int s = nci_snep_put(dev, ndef, nl);
    Serial.printf("snep_put: %s\n", s == NCI_OK ? "OK" : nci_strerror(s));
    nci_deactivate(dev, NCI_DEACT_DISCOVERY);
    delay(800);
  }
}
