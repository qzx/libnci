project('nci', 'c',
  version: '0.2.0',
  license: 'Apache-2.0',
  default_options: ['c_std=c11', 'warning_level=3', 'werror=false'])

libgpiod  = dependency('libgpiod', version: '>=2.0')
libcrypto = dependency('libcrypto', version: '>=3.0')   # OpenSSL: AES/CMAC
libthreads = dependency('threads')                       # async discovery worker

inc_all    = include_directories('include', 'src')
inc_public = include_directories('include')

# --- core library ---------------------------------------------------------
# Hardware/transport layer + chipset drivers + generic device core + the pure
# card-application and protocol layers. pn7160 is one chipset under src/chips/.
nci_sources = [
  'src/gpio.c', 'src/i2c.c', 'src/transport.c',
  'src/nci.c', 'src/chipset.c', 'src/chips/pn7160.c', 'src/device.c',
  'src/t4t.c', 'src/mifare.c', 'src/mfc_ndef.c', 'src/ndef.c', 'src/ndef_build.c',
  'src/desfire.c', 'src/desfire_ev2.c', 'src/desfire_ev3.c', 'src/desfire_legacy.c',
  'src/desfire_lrp.c', 'src/desfire_dam.c',
  'src/crypto.c', 'src/crc.c', 'src/sdm.c', 'src/lrp.c', 'src/log.c',
]

nci_lib = static_library('nci',
  nci_sources,
  include_directories: inc_all,
  dependencies: [libgpiod, libcrypto, libthreads],
  install: true)

nci_dep = declare_dependency(
  include_directories: inc_public,
  link_with: nci_lib)

# Back-compat aliases for downstreams that referenced the old names.
hcinfc_dep = nci_dep
pn7160_dep = nci_dep

# --- demo / CLI apps -------------------------------------------------------
foreach app : ['nfc-detect', 'nfc-read-ndef', 'desfire-info', 'desfire-auth',
               'desfire-manage', 'desfire-ev3-test', 'desfire-session-test',
               'desfire-format-ndef', 'nfc-poll', 'ntag424-sdm', 'ntag424-provision',
               'desfire-dam']
  executable(app, 'apps' / (app + '.c'),
    include_directories: inc_public,
    link_with: nci_lib,
    dependencies: [libgpiod, libcrypto, libthreads],
    install: true)
endforeach

# --- installed headers + pkg-config (impl.txt #137, #139) -----------------
install_subdir('include/nci', install_dir: get_option('includedir'))

import('pkgconfig').generate(nci_lib,
  name: 'libnci',
  description: 'Modern NFC reader/writer stack (PN7160 and other NCI controllers)',
  subdirs: '.',
  requires_private: ['libcrypto'],
  extra_cflags: [])

# --- unit tests: pure layers, no libgpiod, no hardware --------------------
test_nci = executable('test_nci',
  ['tests/test_nci.c', 'src/nci.c', 'src/log.c'],
  include_directories: inc_all)
test('nci', test_nci)

# card application layers (T4T NDEF / NDEF parse / DESFire) vs a mock apdu_fn
test_cards = executable('test_cards',
  ['tests/test_cards.c', 'src/t4t.c', 'src/mifare.c', 'src/mfc_ndef.c', 'src/ndef.c',
   'src/desfire.c', 'src/desfire_ev2.c', 'src/desfire_ev3.c', 'src/crypto.c', 'src/log.c'],
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

# NTAG 424 DNA SDM / SUN verifier (AN12196 primitives)
test_sdm = executable('test_sdm',
  ['tests/test_sdm.c', 'src/sdm.c', 'src/crypto.c', 'src/log.c'],
  include_directories: inc_all,
  dependencies: [libcrypto])
test('sdm', test_sdm)
