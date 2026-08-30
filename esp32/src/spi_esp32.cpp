/* SPDX-License-Identifier: Apache-2.0 */
/*
 * spi_esp32.cpp - ESP32 SPI byte pipe for libnci (replaces the Linux src/spi.c).
 *
 * A near-verbatim port of the ElectronicCats/elechouse vendor driver's SPI transport
 * (Electroniccats_PN7150.cpp writeData/readData) - the reference driver for this exact PN7161
 * SPI board - onto the SAME Arduino SPIClass it uses. Raw ESP-IDF spi_master framing did not
 * reproduce the vendor's multi-packet reads on the C6 (managed CS reads the RSP but over-clocks
 * past it; manual CS times the NSS edge wrong); using SPIClass.transfer() byte-by-byte, exactly
 * as the vendor does, is the proven path.
 *
 * The sketch selects the bus pins + CS BEFORE nci_open():
 *     nci_esp32_spi_set_pins(SCK, MISO, MOSI, CS);   // e.g. (6, 2, 7, 5) on ESP32-C6
 *
 * Framing (mode 0, MSB-first, 1 MHz, manual CS held low across a whole transfer):
 *   - TDD byte leads every transfer: 0x7F = host writes, 0xFF = host reads.
 *   - WRITE: CS low, transfer 0x7F; if its MISO echo is 0xFF the NFCC is ready - transfer the
 *     command bytes; else CS high, wait, retry (standby/busy).
 *   - READ: CS low, transfer 0xFF; if its echo is 0xFF, transfer 3 header bytes, then EXACTLY
 *     header[2] payload bytes; CS high. Reading the exact length (not an over-read) is what
 *     lets the following packet (e.g. the CORE_RESET_NTF after the RSP) present correctly.
 *
 * nci_spi.h declares these extern "C", so the definitions inherit C linkage.
 */
#include <Arduino.h>
#include <SPI.h>
#include <stdlib.h>
#include <string.h>
#include "nci_spi.h"

#define TDD_WRITE   0x7F
#define TDD_READ    0xFF
#define MISO_READY  0xFF        /* NFCC readiness echo against the TDD byte */
#define WRITE_TRIES 3           /* vendor retries the write-TDD handshake 3x */

struct nci_spi { SPIClass *spi; int cs; uint32_t hz; };

/* Pins chosen by the sketch before nci_open(). */
static int s_sck = -1, s_miso = -1, s_mosi = -1, s_cs = -1;

extern "C" void nci_esp32_spi_set_pins(int sck, int miso, int mosi, int cs)
{
    s_sck = sck; s_miso = miso; s_mosi = mosi; s_cs = cs;
}

nci_spi *nci_spi_open(const char *dev, uint32_t speed_hz, uint8_t mode)
{
    (void)dev; (void)mode;                              /* pins from set_pins(); PN7160 = mode 0 */
    if (s_sck < 0 || s_miso < 0 || s_mosi < 0 || s_cs < 0) return NULL;

    nci_spi *s = (nci_spi *)calloc(1, sizeof(nci_spi));
    if (!s) return NULL;
    s->spi = &SPI;
    s->cs  = s_cs;
    s->hz  = speed_hz ? speed_hz : NCI_SPI_DEFAULT_HZ;  /* default 1 MHz */

    pinMode(s->cs, OUTPUT);
    digitalWrite(s->cs, HIGH);                          /* idle high */
    s->spi->begin(s_sck, s_miso, s_mosi, s_cs);         /* SCK, MISO, MOSI, SS */
    return s;
}

void nci_spi_close(nci_spi *s)
{
    if (!s) return;
    if (s->spi) s->spi->end();
    free(s);
}

/* Write: CS low, 0x7F then the NCI bytes; if the echo against 0x7F is 0xFF the NFCC accepted
 * them, else back off and resend (0x7F nudges it awake). Returns len when accepted, -1 after
 * WRITE_TRIES (the NCI command() layer then resends). */
int nci_spi_write(nci_spi *s, const uint8_t *buf, size_t len)
{
    if (!s || !buf || len == 0) return -1;
    for (int attempt = 0; attempt < WRITE_TRIES; attempt++) {
        s->spi->beginTransaction(SPISettings(s->hz, MSBFIRST, SPI_MODE0));
        digitalWrite(s->cs, LOW);
        uint8_t echo = s->spi->transfer(TDD_WRITE);
        if (echo == MISO_READY) {
            for (size_t i = 0; i < len; i++) s->spi->transfer(buf[i]);
            digitalWrite(s->cs, HIGH);
            s->spi->endTransaction();
            return (int)len;
        }
        digitalWrite(s->cs, HIGH);
        s->spi->endTransaction();
        delay(5);                                       /* not ready: back off, resend */
    }
    return -1;
}

/* Read ONE complete NCI packet - EXACTLY header(3) + payload(header[2]) - byte by byte with CS
 * held. Returns the packet length, 0 when not ready / the line is idle (caller resends), or <0
 * when the caller buffer is too small. */
int nci_spi_read(nci_spi *s, uint8_t *buf, size_t cap)
{
    if (!s || !buf || cap < 3) return -1;

    s->spi->beginTransaction(SPISettings(s->hz, MSBFIRST, SPI_MODE0));
    digitalWrite(s->cs, LOW);

    s->spi->transfer(TDD_READ);                         /* direction byte; its echo is a turnaround */
    buf[0] = s->spi->transfer(0x00);
    buf[1] = s->spi->transfer(0x00);
    buf[2] = s->spi->transfer(0x00);
    /* all-0xFF = idle (no data staged); all-0x00 = the measured pre-IRQ busy window (the chip
     * drives MISO low for a few ms while waking/processing before it asserts IRQ). Both mean "no
     * packet this window" - caller keeps polling. NOTE: test all THREE header bytes for the
     * busy window - a real NCI DATA packet on Conn 0 (NFC-DEP / ISO-DEP payloads) starts with
     * byte0 == 0x00, so gating on byte0 alone would silently drop every data packet. */
    if ((buf[0] == 0xFF && buf[1] == 0xFF && buf[2] == 0xFF) ||
        (buf[0] == 0x00 && buf[1] == 0x00 && buf[2] == 0x00)) {
        digitalWrite(s->cs, HIGH);
        s->spi->endTransaction();
        return 0;
    }

    size_t plen = buf[2];
    if (3 + plen > cap) {
        digitalWrite(s->cs, HIGH);
        s->spi->endTransaction();
        return -1;
    }
    for (size_t i = 0; i < plen; i++) buf[3 + i] = s->spi->transfer(0x00);

    digitalWrite(s->cs, HIGH);
    s->spi->endTransaction();
    return (int)(3 + plen);
}
