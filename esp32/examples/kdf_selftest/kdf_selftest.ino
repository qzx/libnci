// SPDX-License-Identifier: Apache-2.0
//
// kdf_selftest - proves libnci's key-derivation math (nci/kdf.h) compiles,
// links and runs on ESP32 against the bundled mbedTLS crypto backend
// (crypto_esp32.c) with NO OpenSSL. It reproduces the qzxspec "0014" node-key
// golden vector on-device:
//
//   worldKey = 0x86..0x95, uid = 04A2C7B19E6F80, random = 706F772E63AABBCCDD
//   -> fileKey = b5e83f069dc606c1f72823ebc1716941
//
// nci_derive_node_key is the SINGLE source of this derivation for the whole
// stack (host OpenSSL + ESP32 mbedTLS route through the same kdf.c). Compile
// alone proves the linkage; flashing prints PASS/FAIL + the key over serial.
//
//   arduino-cli compile -b esp32:esp32:makergo_c6_supermini:CDCOnBoot=cdc \
//       examples/kdf_selftest
#include <libnci.h>

static const uint8_t EXPECT[16] = {
  0xb5,0xe8,0x3f,0x06,0x9d,0xc6,0x06,0xc1,
  0xf7,0x28,0x23,0xeb,0xc1,0x71,0x69,0x41
};

void setup() {
  Serial.begin(115200);
  delay(300);

  uint8_t wk[16];
  for (int i = 0; i < 16; i++) wk[i] = (uint8_t)(0x86 + i);
  uint8_t uid[7] = {0x04,0xA2,0xC7,0xB1,0x9E,0x6F,0x80};
  uint8_t rnd[9] = {0x70,0x6F,0x77,0x2E,0x63,0xAA,0xBB,0xCC,0xDD};

  // The linchpin: UID-bound node key = truncate16(HMAC-SHA256(wk, uid||random)).
  uint8_t key[16];
  int rc = nci_derive_node_key(wk, 16, uid, 7, rnd, 9, key);

  // Exercise the other kdf.c primitives so the linker must resolve them too:
  // HMAC-SHA256 (RFC 4231 TC1) and the AN10922 TDEA-CMAC diversification path
  // (nci_diversify_2k3des -> crypto_tdea_cmac on mbedTLS DES).
  uint8_t hk[20]; memset(hk, 0x0b, 20);
  uint8_t mac[32];
  int rc2 = nci_hmac_sha256(hk, 20, (const uint8_t *)"Hi There", 8, mac);
  uint8_t d16[16];
  int rc3 = nci_diversify_2k3des(wk, uid, 7, d16);

  bool ok = (rc == 0) && (memcmp(key, EXPECT, 16) == 0);
  Serial.printf("nci_derive_node_key rc=%d  0014-vector %s\n", rc, ok ? "PASS" : "FAIL");
  Serial.printf("nci_hmac_sha256 rc=%d  nci_diversify_2k3des rc=%d\n", rc2, rc3);
  Serial.print("fileKey = ");
  for (int i = 0; i < 16; i++) Serial.printf("%02x", key[i]);
  Serial.println();
}

void loop() {}
