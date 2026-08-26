/* SPDX-License-Identifier: Apache-2.0 */
/*
 * test_desfire_hl - unit tests for the PURE GetFileSettings parser
 * (nci_desfire_parse_file_settings) against crafted response byte strings.
 *
 * Only the parser is card-free and therefore unit-tested here. The other
 * high-level flows in src/desfire_hl.c - nci_desfire_read_file,
 * nci_desfire_value_op, nci_desfire_picc_to_aes, nci_reacquire[_uid] - are
 * orchestration over the live NCI/DESFire stack (real select / authenticate /
 * transceive / discovery). They are INTEGRATION-only and are not mock-tested
 * in this file.
 */
#include "nci/desfire_hl.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

/* Standard data file: [type=00][opt=00 plain][access:2 LE][size:3 LE]. */
static void test_std_data_file(void)
{
    /* access_rights 0xEEE0, size 256 (0x000100). */
    const uint8_t buf[] = { 0x00, 0x00, 0xE0, 0xEE, 0x00, 0x01, 0x00 };
    nci_desfire_file_info fi;
    assert(nci_desfire_parse_file_settings(buf, sizeof buf, &fi) == NCI_OK);
    assert(fi.type == 0x00);
    assert(fi.comm == 0x00);                 /* Plain */
    assert(fi.access_rights == 0xEEE0);
    assert(fi.size == 256);
    assert(fi.file_option == 0x00);
    assert(fi.sdm == false);
    printf("  std_data_file: OK (size=%u, access=%04X)\n",
           fi.size, fi.access_rights);
}

/* Standard data file with Full comm and a large size. */
static void test_std_data_full_comm(void)
{
    /* opt=0x03 (Full), size 0x0000FF = 255. */
    const uint8_t buf[] = { 0x00, 0x03, 0x11, 0xF3, 0xFF, 0x00, 0x00 };
    nci_desfire_file_info fi;
    assert(nci_desfire_parse_file_settings(buf, sizeof buf, &fi) == NCI_OK);
    assert(fi.comm == 0x03);                 /* Full */
    assert(fi.size == 255);
    assert(fi.access_rights == 0xF311);
    assert(fi.sdm == false);
    printf("  std_data_full_comm: OK (comm=Full, size=%u)\n", fi.size);
}

/* Value file: [type=02][opt][access:2][Lower:4][Upper:4][LimCredit:4][flags]. */
static void test_value_file(void)
{
    uint8_t buf[17];
    memset(buf, 0, sizeof buf);
    buf[0] = 0x02;          /* value file */
    buf[1] = 0x01;          /* MAC comm */
    buf[2] = 0x21; buf[3] = 0x43;   /* access 0x4321 */
    /* limits/value bytes are irrelevant to the parse; leave them zero. */
    nci_desfire_file_info fi;
    assert(nci_desfire_parse_file_settings(buf, sizeof buf, &fi) == NCI_OK);
    assert(fi.type == 0x02);
    assert(fi.comm == 0x01);                 /* MAC */
    assert(fi.access_rights == 0x4321);
    assert(fi.size == 0);                    /* value files have no byte size */
    printf("  value_file: OK (comm=MAC, size=%u)\n", fi.size);
}

/* Linear record file: RecordSize(3) MaxRecords(3) CurrentRecords(3). */
static void test_record_file(void)
{
    const uint8_t buf[] = {
        0x03, 0x00, 0x00, 0xF0,        /* type, opt, access:2 */
        0x20, 0x00, 0x00,              /* RecordSize = 32     */
        0x0A, 0x00, 0x00,              /* MaxRecords = 10     */
        0x03, 0x00, 0x00,              /* CurrentRecords = 3  */
    };
    nci_desfire_file_info fi;
    assert(nci_desfire_parse_file_settings(buf, sizeof buf, &fi) == NCI_OK);
    assert(fi.type == 0x03);
    assert(fi.size == 32);                   /* per-record size */
    assert(fi.sdm == false);
    printf("  record_file: OK (rec_size=%u)\n", fi.size);
}

/* SDM standard data file: FileOption bit6 set, SDMOptions + SDMAccessRights
 * follow the 3-byte size. Modeled on an NTAG 424 DNA file-02 SUN config. */
static void test_sdm_file(void)
{
    const uint8_t buf[] = {
        0x00, 0x40,                    /* std data, FileOption bit6 (SDM), comm plain */
        0x00, 0xE0,                    /* access rights */
        0x00, 0x01, 0x00,              /* size = 256 */
        0xC1,                          /* SDMOptions */
        0x21, 0xF1,                    /* SDMAccessRights = 0xF121 (LE) */
    };
    nci_desfire_file_info fi;
    assert(nci_desfire_parse_file_settings(buf, sizeof buf, &fi) == NCI_OK);
    assert(fi.type == 0x00);
    assert(fi.comm == 0x00);
    assert(fi.size == 256);
    assert(fi.sdm == true);
    assert(fi.file_option == 0x40);
    assert(fi.sdm_options == 0xC1);
    assert(fi.sdm_access_rights == 0xF121);
    printf("  sdm_file: OK (sdm_opts=%02X, sdm_ar=%04X)\n",
           fi.sdm_options, fi.sdm_access_rights);
}

/* Malformed / boundary inputs. */
static void test_errors(void)
{
    nci_desfire_file_info fi;
    const uint8_t ok[] = { 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00 };

    assert(nci_desfire_parse_file_settings(NULL, 7, &fi) == NCI_E_INVAL);
    assert(nci_desfire_parse_file_settings(ok, 7, NULL) == NCI_E_INVAL);

    /* Shorter than the 4-byte header. */
    assert(nci_desfire_parse_file_settings(ok, 3, &fi) == NCI_E_PROTO);

    /* Standard data header present but the 3-byte size is truncated. */
    assert(nci_desfire_parse_file_settings(ok, 5, &fi) == NCI_E_PROTO);

    /* SDM bit set but the SDMOptions/SDMAccessRights bytes are missing. */
    const uint8_t sdm_short[] = { 0x00, 0x40, 0x00, 0xE0, 0x10, 0x00, 0x00 };
    assert(nci_desfire_parse_file_settings(sdm_short, sizeof sdm_short, &fi)
           == NCI_E_PROTO);

    /* Value file body too short. */
    const uint8_t val_short[] = { 0x02, 0x01, 0x00, 0x00, 0x00 };
    assert(nci_desfire_parse_file_settings(val_short, sizeof val_short, &fi)
           == NCI_E_PROTO);

    printf("  errors: OK (INVAL + PROTO boundaries)\n");
}

int main(void)
{
    printf("test_desfire_hl:\n");
    test_std_data_file();
    test_std_data_full_comm();
    test_value_file();
    test_record_file();
    test_sdm_file();
    test_errors();
    printf("all tests passed\n");
    return 0;
}
