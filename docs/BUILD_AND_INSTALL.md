# Building, installing, and consuming libnci

## Dependencies

| Requirement | Why | Debian/RPi OS package |
|---|---|---|
| Meson ≥ 0.63, Ninja | build system | `meson ninja-build` |
| C11 compiler | the library is C11 | `gcc` / `clang` |
| **libgpiod ≥ 2.0** | GPIO (VEN/IRQ/DWL) via libgpiod v2 | `libgpiod-dev` |
| **OpenSSL ≥ 3 (libcrypto)** | AES/CMAC/3DES/CRC32 for DESFire/NTAG/LRP/SDM | `libssl-dev` |
| pthreads | async discovery worker | (toolchain) |

```bash
sudo apt install meson ninja-build libgpiod-dev libssl-dev    # trixie+ / Pi OS
```

> libgpiod **v2** is required — the v1 API is incompatible and the library does
> not support it. On older distros you may need to build libgpiod 2.x from
> source.

## Build

```bash
meson setup build
meson compile -C build
meson test    -C build      # 7 suites, all hardware-free
```

The build produces the library, the [CLI tools](CLI_TOOLS.md) (e.g.
`build/nfc-poll`, `build/nfc-write-ndef`), and the unit-test binaries.

## Build options

Set with `meson setup build -D<opt>=<val>` or `meson configure build -D…`.

| Option | Default | Effect |
|---|---|---|
| `default_library` | `both` | `shared` builds only `libnci.so*`; `static` only `libnci.a`; `both` builds both (the project default). |
| `prefix` | `/usr/local` | install prefix |
| `buildtype` | `debug` | `release` / `debugoptimized` for optimized builds |
| `warning_level` | `3` | project default; warnings are not errors (`werror=false`) |

The library version is **1.0.0-alpha.1** (alpha: the API/ABI may still change).
The shared object carries **soversion 0** (`libnci.so.0`) to signal that the
ABI is not yet stable; it is bumped to 1 at the first stable release.

## Install

```bash
sudo meson install -C build
sudo ldconfig                 # refresh the shared-library cache
```

With the default prefix this installs:

| What | Path (multiarch shown for aarch64) |
|---|---|
| Headers | `/usr/local/include/nci/*.h` |
| Shared library | `/usr/local/lib/<triplet>/libnci.so.1.0.0` + `libnci.so.0` + `libnci.so` |
| Static library | `/usr/local/lib/<triplet>/libnci.a` |
| pkg-config | `/usr/local/lib/<triplet>/pkgconfig/libnci.pc` |
| CMake package | `/usr/local/lib/<triplet>/cmake/libnci/libnciConfig.cmake` (+ version file) |
| man pages | `/usr/local/share/man/man1/{nfc-detect,nfc-poll,nfc-read-ndef,nfc-write-ndef,ntag424-sdm}.1` |
| CLI tools | `/usr/local/bin/*` |

To install somewhere else: `meson install -C build --destdir /tmp/stage`, or
configure a different `prefix`.

## Consuming libnci from another project

### pkg-config / plain Make

```bash
pkg-config --modversion libnci          # 1.0.0-alpha.1
pkg-config --cflags libnci              # -I/usr/local/include
pkg-config --libs   libnci              # -L/usr/local/lib/<triplet> -lnci

cc myapp.c $(pkg-config --cflags --libs libnci) -o myapp
```

```c
#include <nci/nci.h>      /* and <nci/desfire.h>, <nci/ndef.h>, <nci/sdm.h>, … */
```

`libnci.pc` declares its private dependencies (`Requires.private: libcrypto,
libgpiod`; `Libs.private: -pthread`) so a **static** link
(`pkg-config --static --libs libnci`) resolves the full transitive closure.

### Meson

```meson
nci_dep = dependency('libnci')          # found via pkg-config
executable('myapp', 'myapp.c', dependencies: nci_dep)
```

### CMake

```cmake
find_package(libnci CONFIG REQUIRED)
add_executable(myapp myapp.c)
target_link_libraries(myapp PRIVATE libnci::nci)
```

`find_package(libnci CONFIG)` loads `libnciConfig.cmake`, which pulls in
`OpenSSL` and `Threads` (and `libgpiod` via pkg-config when available) and
defines the imported target **`libnci::nci`** with the right include dir and
link libraries. The version-compatibility file uses the numeric base `1.0.0`
(the `-alpha.N` suffix is dropped for CMake's `VERSION_LESS`/`VERSION_EQUAL`
comparisons).

### Non-standard prefix

If you installed to a prefix that is not on the default search paths:

```bash
export PKG_CONFIG_PATH=/opt/nci/lib/pkgconfig:$PKG_CONFIG_PATH      # pkg-config / Meson
cmake -DCMAKE_PREFIX_PATH=/opt/nci ...                             # CMake
export LD_LIBRARY_PATH=/opt/nci/lib:$LD_LIBRARY_PATH               # runtime loader
```

## Runtime access (permissions)

The tools open `/dev/i2c-N` and a GPIO chip. Either run as root, or add your
user to the `i2c` and `gpio` groups, and enable I2C
(`dtparam=i2c_arm=on`, e.g. via `raspi-config`). See [HARDWARE.md](HARDWARE.md).

## Verifying an install

```bash
pkg-config --exists libnci && echo "pkg-config: OK"
printf '#include <nci/nci.h>\nint main(void){return (int)nci_chipset_count()-1;}\n' > /tmp/t.c
cc /tmp/t.c $(pkg-config --cflags --libs libnci) -o /tmp/t && /tmp/t && echo "link+run: OK"
```
