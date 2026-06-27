/* SPDX-License-Identifier: Apache-2.0 */
/*
 * test_lrp - Leakage Resilient Primitive against the NXP AN12304 test vectors
 * (docs/LRP.txt). Pure, no hardware.
 */
#include "lrp.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

/* hex string -> bytes; returns byte count */
static size_t hx(const char *s, uint8_t *out)
{
    size_t n = 0;
    for (; s[0] && s[1]; s += 2) {
        unsigned v; sscanf(s, "%2x", &v); out[n++] = (uint8_t)v;
    }
    return n;
}
/* hex string -> nibbles (each char one nibble); returns nibble count */
static size_t hxn(const char *s, uint8_t *out)
{
    size_t n = 0;
    for (; *s; s++) {
        char c = *s;
        uint8_t v = (c >= '0' && c <= '9') ? (uint8_t)(c - '0')
                  : (c >= 'A' && c <= 'F') ? (uint8_t)(c - 'A' + 10)
                  : (uint8_t)(c - 'a' + 10);
        out[n++] = v;
    }
    return n;
}
static int eqh(const uint8_t *b, const char *hex)
{
    uint8_t e[64]; size_t n = hx(hex, e);
    return memcmp(b, e, n) == 0;
}

static void test_genkeys(void)
{
    uint8_t bk[16]; hx("567826B8DA8E768432A9548DBE4AA3A0", bk);
    lrp_ctx c; lrp_init(&c, bk);
    assert(eqh(c.p[0],  "AC20D39F5341FE98DFCA21DA86BA7914"));
    assert(eqh(c.p[1],  "907DA03D672449166915E4563E089D6D"));
    assert(eqh(c.p[15], "71B444AF257A93215311D758DD333247"));
    assert(eqh(c.uk[0], "163D14ED24ED935373568EC521E96CF4"));
    assert(eqh(c.uk[1], "1C519C000208B95A39A65DB058327188"));
    assert(eqh(c.uk[2], "FE30AB50467E61783BFE6B5E0560160E"));
    printf("  lrp genkeys: OK\n");
}

struct evkat { const char *key, *iv; int fin, uk; const char *res; };
static void test_eval(void)
{
    static const struct evkat v[] = {
        {"567826B8DA8E768432A9548DBE4AA3A0","1359",1,2,"1BA2C0C578996BC497DD181C6885A9DD"},
        {"B65557CE0E9B4C5886F232200113562B","BB4FCF27C94076F756AB030D",0,1,"6FDFA8D2A6AA8476BF94E71F25637F96"},
        {"88B95581002057A93E421EFE4076338B","77299D",1,2,"E9C04556A214AC3297B83E4BDF46F142"},
        {"C48A8E8B16571645A1557825AA66AC91","1F0B7C0DB12889CA436CABB78BE42F9",1,3,"51296B5E6D3B8DB8A1A7399760A19189"},
        {"99B1647A76CD170EA07997043E1E7919","F",1,1,"BA5F895E8B57F7753EE5C7276E60B37F"},
        {"1000076C2934BDB02750204704DAA472","8C3E0",1,2,"581C3B057F9312FECF4A7B8070C83B8C"},
        {"75FCA5E188F44F1E808597A0B7B690D4","64962F5DED0468F1",1,1,"EBD6F32ED75566E6756A14EC16715CBD"},
        {"A14E397DA6C410440FA9EC4C61774094","4B42600D",1,0,"21C0B442BF41B7DDD80D4A99CD7B7B81"},
    };
    for (size_t i = 0; i < sizeof v / sizeof v[0]; i++) {
        uint8_t bk[16], nib[64], out[16];
        hx(v[i].key, bk);
        size_t nn = hxn(v[i].iv, nib);
        lrp_ctx c; lrp_init(&c, bk);
        lrp_eval(&c, v[i].uk, nib, nn, v[i].fin, out);
        assert(eqh(out, v[i].res));
    }
    printf("  lrp eval: OK (%zu vectors)\n", sizeof v / sizeof v[0]);
}

struct cmkat { const char *key, *msg, *mac; };
static void test_cmac(void)
{
    static const struct cmkat v[] = {
        {"63A0169B4D9FE42C72B2784C806EAC21","","0E07C601970814A4176FDA633C6FC3DE"},
        {"8195088CE6C393708EBBE6C7914ECB0B","BBD5B85772C7","AD8595E0B49C5C0DB18E77355F5AAFF6"},
        {"7860B864632C6C8BC9A4C06D49D7E2AE","DC7F","59D3D3A4307A3BBD8E8E5F4B8E75510D"},
        {"A418BA1658A6F0D90830C58679F80AC4","06","FF9561CC6E45FFFD4388003AA5F61233"},
        {"C960E0C80D89728D1FF952EFF5B83FEE","21","4EBEE65E5DD0C30F89C8ED49A3D2BF32"},
        {"57A2DD3D6DAB16AFC1D07B277664ED82","D2D728DE057B3E","DBDEC069CF2B46450CEFB34FFD80D840"},
    };
    for (size_t i = 0; i < sizeof v / sizeof v[0]; i++) {
        uint8_t bk[16], msg[256], mac[16];
        hx(v[i].key, bk);
        size_t ml = hx(v[i].msg, msg);
        lrp_ctx c; lrp_init(&c, bk);
        lrp_cmac(&c, msg, ml, mac);
        assert(eqh(mac, v[i].mac));
    }
    printf("  lrp cmac: OK (%zu vectors)\n", sizeof v / sizeof v[0]);
}

struct lrkat { const char *key, *iv, *pt, *ct; int pad; };
static void test_lricb(void)
{
    static const struct lrkat v[] = {
        {"E0C4935FF0C254CD2CEF8FDDC32460CF","C3315DBF","012D7F1653CAF6503C6AB0C1010E8CB0",
         "FCBBACAA4F29182464F99DE41085266F480E863E487BAAF687B43ED1ECE0D623",1},
        {"EFA5B7429CD153BF0086DEF900C0F235","9036FFFF","E7F61E012F4F3255312BA68B1D2FDABF",
         "EA6E09AC2FB97E102D8CA64C1CBC0C0C",0},
        {"15CDECFC507C777B31CA4D6562D809F2","5B29FFFF","AA8EC68E0519914D8F00CFD8EA226B7E",
         "C8FBD3842E69C8E2EBCA96CE28AB02F0",0},
        {"3CEEB70C13578D714860EEE19DBC8B01","104988FF","3E1537842F53FFD5AD788DC6C0A14D25",
         "0EFEEAE6249011EF6CD2D28980B93766",0},
    };
    for (size_t i = 0; i < sizeof v / sizeof v[0]; i++) {
        uint8_t bk[16], ctr[8], pt[256], ct[256], out[256];
        hx(v[i].key, bk);
        hx(v[i].iv, ctr);
        size_t pl = hx(v[i].pt, pt);
        size_t cl = hx(v[i].ct, ct);
        lrp_ctx c; lrp_init(&c, bk);
        /* For padding cases the PT is one block and the CT carries the extra
         * mandatory pad block; feed an explicitly padded buffer. */
        uint8_t in[256]; size_t il = pl;
        memcpy(in, pt, pl);
        if (v[i].pad) { in[il++] = 0x80; while (il % 16) in[il++] = 0x00; }
        assert(lrp_lricb(&c, 0, ctr, in, il, out, 1) == 0);
        assert(il == cl && memcmp(out, ct, cl) == 0);
        /* round-trip decrypt */
        uint8_t back[256];
        assert(lrp_lricb(&c, 0, ctr, ct, cl, back, 0) == 0);
        assert(memcmp(back, in, il) == 0);
    }
    printf("  lrp lricb: OK (%zu vectors)\n", sizeof v / sizeof v[0]);
}

int main(void)
{
    printf("test_lrp:\n");
    test_genkeys();
    test_eval();
    test_cmac();
    test_lricb();
    printf("all tests passed\n");
    return 0;
}
