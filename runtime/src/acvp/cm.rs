// Licensed under the Apache-2.0 license

//! Cryptographic-mailbox encrypt targets (CMK, AES / AES-GCM / ECDH / SHAKE256 contexts).

use super::{invalid, read_array, Fields, Outcome};
use crate::cryptographic_mailbox::acvp_state::Kind;
use crate::Drivers;
use caliptra_api::mailbox::*;
use caliptra_drivers::LEArray4x8;
use caliptra_error::CaliptraResult;
use zerocopy::transmute;

/// Fields: [key 32][plaintext]. Response data: iv || ciphertext || tag.
pub(crate) fn encrypt(
    drivers: &mut Drivers,
    target: u32,
    fields: &mut Fields,
    out: &mut [u8],
) -> CaliptraResult<Outcome> {
    let kind = match target {
        ACVP_TARGET_CM_ENCRYPT_CMK => Kind::Cmk,
        ACVP_TARGET_CM_ENCRYPT_AES_CONTEXT => Kind::AesContext,
        ACVP_TARGET_CM_ENCRYPT_AES_GCM_CONTEXT => Kind::AesGcmContext,
        ACVP_TARGET_CM_ENCRYPT_ECDH_CONTEXT => Kind::EcdhContext,
        ACVP_TARGET_CM_ENCRYPT_SHAKE256_CONTEXT => Kind::Shake256Context,
        _ => return Err(invalid()),
    };
    let key_bytes: [u8; 32] = read_array(fields.next()?)?;
    let key: LEArray4x8 = transmute!(key_bytes);
    let pt = fields.next()?;
    // Plaintexts are at most 128 bytes. Copy them out of the mailbox with byte loads.
    let mut buf = [0u8; 128];
    let dst = buf.get_mut(..pt.len()).ok_or_else(invalid)?;
    for (d, s) in dst.iter_mut().zip(pt.iter()) {
        // SAFETY: `s` is a reference into the request field, valid and aligned for a u8 read.
        *d = unsafe { core::ptr::read_volatile(s) };
    }
    let n = drivers.cryptographic_mailbox.acvp_encrypt(
        &mut drivers.aes,
        &mut drivers.trng,
        kind,
        key,
        &buf[..pt.len()],
        out,
    )?;
    Ok(Outcome::Data(n))
}
