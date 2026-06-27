/* SPDX-License-Identifier: Apache-2.0 */
/*
 * desfire_dam.h (internal) - DESFire EV2/EV3 Delegated Application Management
 * (impl.txt #101). A third party holding the DAM keys creates an application in
 * a DAM slot, authorised by a DAMMAC. Ported (clean-room) from the Proxmark3
 * `hf mfdes createdelegateapp` reference (AES DAM keys):
 *
 *   appdata    = AID(3,LE) || DAMSlot(2,LE) || SlotVer(1) || Quota(2,LE) ||
 *                KS1(1) || KS2(1) [|| KS3 || ISOfid(2,LE) || DFname]
 *   cryptogram = AES-CBC-enc(DAMEncKey, 7*rand || dstKey || dstKeyVer || 0-pad32, IV0)
 *   DAMMAC     = trunc_even(AES-CMAC(DAMMACKey, 0xC9 || appdata || cryptogram))[0..7]
 *   command    = C9<appdata> + AF<cryptogram||DAMMAC>, MACed under an EV2 session
 *                authenticated with DAMAuthKey (key 0x10).
 */
#ifndef PN7160_DESFIRE_DAM_H
#define PN7160_DESFIRE_DAM_H

#include "apdu.h"
#include "desfire_ev2.h"

/* Build the appdata (part 1) and contdata (cryptogram||DAMMAC, part 2) for a
 * delegated app with AES keys. dst_key is the initial app key (16 B). */
void desfire_dam_build(uint32_t aid, uint16_t dam_slot, uint8_t slot_ver,
                       uint16_t quota, uint8_t ks1, uint8_t ks2,
                       const uint8_t dam_enc_key[16], const uint8_t dam_mac_key[16],
                       const uint8_t dst_key[16], uint8_t dst_key_ver,
                       uint8_t appdata[16], size_t *appdata_len,
                       uint8_t contdata[48], size_t *contdata_len);

/* CreateDelegatedApplication (0xC9), in an active EV2 session (auth'd with the
 * DAMAuthKey). Sends C9<appdata> then AF<contdata>, MACed as one command. */
int desfire_dam_create(apdu_fn fn, void *ctx, desfire_ev2_session *s,
                       const uint8_t *appdata, size_t appdata_len,
                       const uint8_t *contdata, size_t contdata_len);

/* GetDelegatedInfo (0x69) for a DAM slot. Returns the 8-byte info
 * (DAMSlotVersion, free blocks, AID at offset 5). MAC mode. */
int desfire_dam_get_info(apdu_fn fn, void *ctx, desfire_ev2_session *s,
                         uint16_t dam_slot, uint8_t out[8]);

#endif /* PN7160_DESFIRE_DAM_H */
