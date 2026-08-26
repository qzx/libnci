project('nci', 'c',
  version: '1.0.0-alpha.1',
  license: 'Apache-2.0',
  default_options: ['c_std=c11', 'warning_level=3', 'werror=false',
                    'default_library=both'])

# Numeric base of the version (drop any -alpha/-rc suffix) for places that
# require a strictly numeric version: the shared-object soname and CMake's
# version-compatibility check.
version_numeric = meson.project_version().split('-')[0]

libcrypto = dependency('libcrypto', version: '>=3.0')   # OpenSSL: AES/CMAC
libthreads = dependency('threads')                       # async discovery worker

# Headless build (no local NFCC): drop the libgpiod/I2C transport + chipset drivers, keep the whole
# protocol + DESFire/NDEF card stack, and reach cards via nci_open_apdu() (host-side crypto, remote
# antenna - the BLE bridge). Forced on any non-Linux host (libgpiod is Linux-only); -Dhardware=false
# selects it on Linux too.
hardware = get_option('hardware') and host_machine.system() == 'linux'

inc_all    = include_directories('include', 'src')
inc_public = include_directories('include')

# --- core library ---------------------------------------------------------
# Generic device core + the pure card-application and protocol layers. These have NO hardware
# dependency: nci.c drives the transport only through a vtable pointer.
nci_sources = [
  'src/nci.c', 'src/device.c', 'src/ce.c',
  'src/t4t.c', 'src/mifare.c', 'src/mfc_ndef.c', 'src/ndef.c', 'src/ndef_build.c',
  'src/ndef_handover.c',
  'src/t2t.c', 'src/t5t.c', 'src/t3t.c', 'src/t1t.c',
  'src/llcp.c', 'src/snep.c',   # P2P: LLCP + SNEP over an activated NFC-DEP link

  'src/desfire.c', 'src/desfire_aes.c', 'src/desfire_ev2.c', 'src/desfire_ev3.c', 'src/desfire_legacy.c',
  'src/desfire_lrp.c', 'src/desfire_dam.c', 'src/desfire_hl.c', 'src/desfire_provision.c',
  'src/crypto.c', 'src/crc.c', 'src/sdm.c', 'src/lrp.c', 'src/log.c',
  'src/originality.c', 'src/kdf.c',
]
nci_deps  = [libcrypto, libthreads]
nci_cargs = []
if hardware
  # Hardware/transport layer + chipset drivers (pn7160/pn7150 under src/chips/).
  nci_sources += ['src/gpio.c', 'src/i2c.c', 'src/spi.c', 'src/transport.c', 'src/chipset.c',
                  'src/chips/pn7160.c', 'src/chips/pn7150.c']
  nci_deps    += dependency('libgpiod', version: '>=2.0')
else
  nci_cargs += '-DNCI_HEADLESS'
endif

# A proper versioned library (impl.txt #138). default_library=both builds the
# shared .so (with an soname) and the static .a; the soname carries soversion 0
# to signal the alpha's ABI is not yet stable. `library()` lets downstreams link
# either form; apps below link against whichever is the default.
nci_lib = library('nci',
  nci_sources,
  version: version_numeric,   # full .so.X.Y.Z symlink
  soversion: '0',             # SONAME: libnci.so.0 (unstable ABI during alpha)
  include_directories: inc_all,
  c_args: nci_cargs,
  dependencies: nci_deps,
  install: true)

nci_dep = declare_dependency(
  include_directories: inc_public,
  link_with: nci_lib)

# Back-compat aliases for downstreams that referenced the old names.
hcinfc_dep = nci_dep
pn7160_dep = nci_dep

# --- demo / CLI apps -------------------------------------------------------
# These open a local NFCC (nci_open), so they only make sense in a hardware build.
if hardware
  foreach app : ['nfc-detect', 'nfc-read-ndef', 'nfc-write-ndef',
                 'desfire-info', 'desfire-auth',
                 'desfire-manage', 'desfire-ev3-test', 'desfire-session-test',
                 'desfire-format-ndef', 'nfc-poll', 'ntag424-sdm', 'ntag424-provision',
                 'desfire-dam']
    executable(app, 'apps' / (app + '.c'),
      include_directories: inc_public,
      link_with: nci_lib,
      dependencies: nci_deps,
      install: true)
  endforeach
endif

# --- installed headers + pkg-config (impl.txt #137, #139) -----------------
install_subdir('include/nci', install_dir: get_option('includedir'))

# pkg-config: downstreams do `pkg-config --cflags --libs libnci`. The private
# requirements let a *static* link resolve the whole transitive closure
# (OpenSSL + libgpiod + pthread) without the consumer naming them.
import('pkgconfig').generate(nci_lib,
  name: 'libnci',
  description: 'Modern NFC reader/writer stack (PN7160 and other NCI controllers)',
  subdirs: '.',
  requires_private: hardware ? ['libcrypto', 'libgpiod'] : ['libcrypto'],
  libraries_private: ['-pthread'],
  extra_cflags: [])

# --- man pages (impl.txt #139) --------------------------------------------
install_man(
  'man/nfc-detect.1', 'man/nfc-poll.1',
  'man/nfc-read-ndef.1', 'man/nfc-write-ndef.1',
  'man/ntag424-sdm.1')

# --- CMake package config (impl.txt #141) ---------------------------------
# So CMake projects can `find_package(libnci CONFIG REQUIRED)` and link the
# imported target `libnci::nci`. Installed next to the lib under cmake/libnci/.
cmake_conf = configuration_data()
cmake_conf.set('VERSION',         meson.project_version())
cmake_conf.set('VERSION_NUMERIC', version_numeric)
cmake_conf.set('includedir', get_option('prefix') / get_option('includedir'))
cmake_conf.set('libdir',     get_option('prefix') / get_option('libdir'))

cmake_install_dir = get_option('libdir') / 'cmake' / 'libnci'
configure_file(
  input:         'cmake/libnciConfig.cmake.in',
  output:        'libnciConfig.cmake',
  configuration: cmake_conf,
  install:       true,
  install_dir:   cmake_install_dir)
configure_file(
  input:         'cmake/libnciConfigVersion.cmake.in',
  output:        'libnciConfigVersion.cmake',
  configuration: cmake_conf,
  install:       true,
  install_dir:   cmake_install_dir)

# --- unit tests: pure layers, no libgpiod, no hardware --------------------
test_nci = executable('test_nci',
  ['tests/test_nci.c', 'src/nci.c', 'src/log.c'],
  include_directories: inc_all)
test('nci', test_nci)

# card application layers (T4T NDEF / NDEF parse / DESFire) vs a mock apdu_fn
test_cards = executable('test_cards',
  ['tests/test_cards.c', 'src/t4t.c', 'src/mifare.c', 'src/mfc_ndef.c', 'src/ndef.c',
   'src/ndef_build.c',
   'src/desfire.c', 'src/desfire_aes.c', 'src/desfire_ev2.c', 'src/desfire_ev3.c', 'src/crypto.c', 'src/log.c'],
  include_directories: inc_all,
  dependencies: [libcrypto])
test('cards', test_cards)

# crypto primitives vs RFC 4493 / FIPS-197 / SP800-38A known-answer vectors
test_crypto = executable('test_crypto',
  ['tests/test_crypto.c', 'src/crypto.c', 'src/log.c'],
  include_directories: inc_all,
  dependencies: [libcrypto])
test('crypto', test_crypto)

# LRP primitive vs the NXP AN12304 test vectors (docs/LRP.txt)
test_lrp = executable('test_lrp',
  ['tests/test_lrp.c', 'src/lrp.c', 'src/crypto.c', 'src/log.c'],
  include_directories: inc_all,
  dependencies: [libcrypto])
test('lrp', test_lrp)

# CRC + protocol utilities (CRC-A/B, ISO15693, FeliCa, ATS/ATQB parsing)
test_crc = executable('test_crc',
  ['tests/test_crc.c', 'src/crc.c', 'src/log.c'],
  include_directories: inc_all)
test('crc', test_crc)

# NDEF parser completions + encoder/builder round-trips
test_ndef = executable('test_ndef',
  ['tests/test_ndef.c', 'src/ndef.c', 'src/ndef_build.c', 'src/log.c'],
  include_directories: inc_all)
test('ndef', test_ndef)

# Tag-type command cores vs RAM-backed fake tags (no NFCC, no libcrypto).
# t2t/t5t/t1t use the inline LOG macros so they link src/log.c; t3t supplies its
# own nci_log_get_level stub, so linking src/log.c there would duplicate it.
test_t2t = executable('test_t2t',
  ['tests/test_t2t.c', 'src/t2t.c', 'src/log.c'],
  include_directories: inc_all)
test('t2t', test_t2t)

test_t5t = executable('test_t5t',
  ['tests/test_t5t.c', 'src/t5t.c', 'src/log.c'],
  include_directories: inc_all)
test('t5t', test_t5t)

test_t3t = executable('test_t3t',
  ['tests/test_t3t.c', 'src/t3t.c'],
  include_directories: inc_all)
test('t3t', test_t3t)

test_t1t = executable('test_t1t',
  ['tests/test_t1t.c', 'src/t1t.c', 'src/log.c'],
  include_directories: inc_all)
test('t1t', test_t1t)

# NTAG 424 DNA SDM / SUN verifier (AN12196 primitives). sdm.c's LRP-SUN path
# (nci_sdm_verify_lrp) pulls in the lrp primitive, so link src/lrp.c too.
test_sdm = executable('test_sdm',
  ['tests/test_sdm.c', 'src/sdm.c', 'src/lrp.c', 'src/crypto.c', 'src/log.c'],
  include_directories: inc_all,
  dependencies: [libcrypto])
test('sdm', test_sdm)

# Legacy-AES (0xAA) DESFire session: the pure session-key derivation KAT plus a
# hardware-free 0xAA handshake against a mock card. desfire_aes.c reaches the
# card through desfire_apdu_raw (desfire.c); crypto.c supplies AES-CBC/CMAC.
test_desfire_aes = executable('test_desfire_aes',
  ['tests/test_desfire_aes.c', 'src/desfire_aes.c', 'src/desfire.c',
   'src/crypto.c', 'src/log.c'],
  include_directories: inc_all,
  dependencies: [libcrypto])
test('desfire_aes', test_desfire_aes)

# DESFire high-level client flows: only the pure GetFileSettings parser
# (nci_desfire_parse_file_settings) is unit-tested; the surrounding one-call
# flows are integration-only. The module's translation unit still references the
# device-layer symbols (select/authenticate/discovery in device.c), whose
# closure is essentially the whole stack, so link the built library rather than
# recompiling a source subset (which would also double-define the pure helper).
test_desfire_hl = executable('test_desfire_hl',
  ['tests/test_desfire_hl.c'],
  include_directories: inc_all,
  link_with: nci_lib,
  dependencies: nci_deps)
test('desfire_hl', test_desfire_hl)

# NTAG 424 SUN provisioning: unit-tests the pure template builder
# (nci_sun_build_template); the live provision_* flows are integration-only but
# their TU pulls in the DESFire/SDM/device closure, so link the library. sdm/AES
# helpers come in transitively via nci_lib.
test_provision = executable('test_provision',
  ['tests/test_provision.c'],
  include_directories: inc_all,
  link_with: nci_lib,
  dependencies: nci_deps)
test('provision', test_provision)

# Fleet-provisioning key derivation (nci/kdf.h): HMAC-SHA256 vs RFC 4231,
# AN10922 AES-128/2K3DES/3K3DES diversification, UID-bound node key. Pure math
# over crypto.c's AES-CMAC + OpenSSL EVP_MAC (HMAC/TDEA-CMAC), so a small source
# subset suffices - no device closure.
test_kdf = executable('test_kdf',
  ['tests/test_kdf.c', 'src/kdf.c', 'src/crypto.c', 'src/log.c'],
  include_directories: inc_all,
  dependencies: [libcrypto])
test('kdf', test_kdf)

# Connection Handover parsing (ndef_handover.c) round-tripped against the
# existing Hs/BT/BLE/Wi-Fi encoders plus hand-built multi-carrier / Hr messages.
# Pure NDEF, no crypto.
test_handover = executable('test_handover',
  ['tests/test_handover.c', 'src/ndef.c', 'src/ndef_build.c',
   'src/ndef_handover.c', 'src/log.c'],
  include_directories: inc_all)
test('handover', test_handover)

# NXP originality signature verification (originality.c): ECDSA-NONE over the UID
# vs the embedded NXP public keys. The pure verifier is exercised with test-time
# keypairs, but the convenience readers (nci_desfire_read_signature / the T2T
# reader) reference the device-layer transceive closure, so link the built
# library rather than a source subset. The test drives OpenSSL directly (EC
# keygen/sign), covered by nci_deps' libcrypto.
test_originality = executable('test_originality',
  ['tests/test_originality.c'],
  include_directories: inc_all,
  link_with: nci_lib,
  dependencies: nci_deps)
test('originality', test_originality)

# Card emulation (listen-mode Type-4 NDEF tag): the pure C-APDU -> R-APDU
# responder plus the session pump (PBF C-APDU reassembly, Conn-0 flow-control
# credits, TX data chaining) driven against a mock transport. ce.c's session
# layer reaches nci_rf_deactivate_idle / nci_rf_discover_map in nci.c and
# t4t_build_cc in t4t.c, so link those; no libcrypto.
test_ce = executable('test_ce',
  ['tests/test_ce.c', 'src/ce.c', 'src/nci.c', 'src/t4t.c', 'src/log.c'],
  include_directories: inc_all)
test('ce', test_ce)

# P2P: the pure LLCP + SNEP codecs, the LLCP data-link state machine, and the
# nci_snep_put/get_link clients driven against a scripted in-memory SNEP peer.
# Pure protocol logic - no NFCC, no libcrypto; the nci-handle façade's two
# device.c symbols are stubbed in the test.
test_p2p = executable('test_p2p',
  ['tests/test_p2p.c', 'src/llcp.c', 'src/snep.c', 'src/log.c'],
  include_directories: inc_all)
test('p2p', test_p2p)
