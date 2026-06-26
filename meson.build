project('pn7160', 'c',
  version: '0.1.0',
  license: 'Apache-2.0',
  default_options: ['c_std=c11', 'warning_level=3', 'werror=false'])

libgpiod  = dependency('libgpiod', version: '>=2.0')
libcrypto = dependency('libcrypto', version: '>=3.0')   # OpenSSL: AES/CMAC

inc_all    = include_directories('include', 'src')
inc_public = include_directories('include')

# --- core static library --------------------------------------------------
pn7160_lib = static_library('pn7160',
  ['src/gpio.c', 'src/i2c.c', 'src/transport.c', 'src/nci.c', 'src/pn7160.c',
   'src/t4t.c', 'src/ndef.c', 'src/desfire.c', 'src/desfire_ev2.c', 'src/crypto.c'],
  include_directories: inc_all,
  dependencies: [libgpiod, libcrypto],
  install: true)

pn7160_dep = declare_dependency(
  include_directories: inc_public,
  link_with: pn7160_lib)

# --- demo apps ------------------------------------------------------------
foreach app : ['nfc-detect', 'nfc-read-ndef', 'desfire-info', 'desfire-auth', 'desfire-manage']
  executable(app, 'apps' / (app + '.c'),
    include_directories: inc_public,
    link_with: pn7160_lib,
    dependencies: [libgpiod, libcrypto],
    install: true)
endforeach

# --- unit tests: pure layers, no libgpiod, no hardware --------------------
test_nci = executable('test_nci',
  ['tests/test_nci.c', 'src/nci.c'],
  include_directories: inc_all)
test('nci', test_nci)

# card application layers (T4T NDEF / NDEF parse / DESFire) vs a mock apdu_fn
test_cards = executable('test_cards',
  ['tests/test_cards.c', 'src/t4t.c', 'src/ndef.c', 'src/desfire.c'],
  include_directories: inc_all)
test('cards', test_cards)

# crypto primitives vs RFC 4493 / FIPS-197 / SP800-38A known-answer vectors
test_crypto = executable('test_crypto',
  ['tests/test_crypto.c', 'src/crypto.c'],
  include_directories: inc_all,
  dependencies: [libcrypto])
test('crypto', test_crypto)
