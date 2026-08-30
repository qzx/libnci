#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Assemble the importable Arduino library zip for ESP32. It bundles the portable
# libnci sources + the ESP32 HAL/crypto backends + the example sketches into the
# layout Arduino IDE expects, then zips it. Output: esp32/dist/libnci-esp32-<ver>.zip
#
#   ./esp32/build-arduino-zip.sh
#   Arduino IDE: Sketch -> Include Library -> Add .ZIP Library... -> pick the zip
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VER="$(grep -m1 "version:" "$ROOT/meson.build" | sed -E "s/.*version: *'([^']+)'.*/\1/")"
STAGE="$ROOT/esp32/dist/stage"
LIB="$STAGE/libnci"
OUTZIP="$ROOT/esp32/dist/libnci-esp32-$VER.zip"

rm -rf "$STAGE"
mkdir -p "$LIB/src/nci" "$LIB/src/chips" "$LIB/examples"

# Portable libnci sources (exclude the Linux-only HAL + the OpenSSL crypto
# backend - both replaced by the ESP32 backends copied in below). kdf.c is
# PORTABLE (its crypto goes through crypto.h -> crypto_esp32.c), so it IS
# bundled: nci_derive_node_key / nci_hmac_sha256 resolve against mbedTLS here.
for f in "$ROOT"/src/*.c "$ROOT"/src/*.h; do
  b="$(basename "$f")"
  case "$b" in i2c.c|gpio.c|crypto.c|spi.c|originality.c) continue ;; esac
  cp "$f" "$LIB/src/$b"
done
cp "$ROOT"/src/chips/*.c          "$LIB/src/chips/"
cp "$ROOT"/include/nci/*.h        "$LIB/src/nci/"      # public headers as <nci/...>
# originality.c is OpenSSL-only (EVP/ECDSA) and is EXCLUDED above; shipping its
# header would advertise nci_*originality* symbols that cannot link on ESP32
# (mbedTLS backend). Drop the header so the package declares nothing unlinkable.
rm -f "$LIB/src/nci/originality.h"
cp "$ROOT"/include/libnci.h       "$LIB/src/libnci.h"  # top-level umbrella = Arduino discovery entry

# ESP32 backends (Wire I2C, Arduino GPIO, mbedTLS crypto).
cp "$ROOT"/esp32/src/*.c "$ROOT"/esp32/src/*.cpp "$LIB/src/"

# Examples + metadata.
cp -r "$ROOT"/esp32/examples/*    "$LIB/examples/"
cp    "$ROOT"/esp32/library.properties "$LIB/library.properties"
[ -f "$ROOT/esp32/README.md" ] && cp "$ROOT/esp32/README.md" "$LIB/README.md" || true
[ -f "$ROOT/LICENSE" ]         && cp "$ROOT/LICENSE"         "$LIB/LICENSE"   || true

rm -f "$OUTZIP"
( cd "$STAGE" && zip -rq "$OUTZIP" libnci )

echo "built: $OUTZIP"
echo "contents:"
( cd "$STAGE" && find libnci -type f | sort | sed 's/^/  /' )
