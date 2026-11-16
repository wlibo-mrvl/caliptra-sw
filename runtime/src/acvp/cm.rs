// Licensed under the Apache-2.0 license

//! Cryptographic-mailbox encrypt targets (CMK, AES / AES-GCM / ECDH / SHAKE256 contexts).

use super::{invalid, read_array, Fields, Outcome};
use crate::cryptographic_mailbox::acvp_state::Kind;
use crate::Drivers;
use caliptra_api::mailbox::*;
use crate::cryptographic_mailbox::Commands;
use caliptra_drivers::{Array4x12, Ecc384PubKey, LEArray4x8};
use caliptra_error::CaliptraError;
use caliptra_error::CaliptraResult;
use zerocopy::IntoBytes;
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

/// Runtime `ecdsa_verify`: runs the real CM_ECDSA_VERIFY handler. The handler (an `acvp` build) verifies
/// against the public key stored here instead of one derived from a CMK seed.
/// Fields: [qx 48][qy 48][r 48][s 48][message].
pub(crate) fn ecdsa_verify(drivers: &mut Drivers, fields: &mut Fields) -> CaliptraResult<Outcome> {
    let qx: [u8; 48] = read_array(fields.next()?)?;
    let qy: [u8; 48] = read_array(fields.next()?)?;
    let r: [u8; 48] = read_array(fields.next()?)?;
    let s: [u8; 48] = read_array(fields.next()?)?;
    let msg = fields.next()?;

    let mut req = CmEcdsaVerifyReq::default();
    if msg.len() > req.message.len() {
        return Err(invalid());
    }
    req.signature_r = r;
    req.signature_s = s;
    req.message_size = msg.len() as u32;
    for (d, b) in req.message.iter_mut().zip(msg.iter()) {
        // SAFETY: `b` is a reference into the request field; a byte read is always aligned.
        *d = unsafe { core::ptr::read_volatile(b) };
    }
    drivers.cryptographic_mailbox.acvp_set_pub_key(Ecc384PubKey {
        x: Array4x12::from(qx),
        y: Array4x12::from(qy),
    });
    let mut resp = [0u8; 8];
    match Commands::ecdsa_verify(drivers, req.as_bytes_partial()?, &mut resp) {
        Ok(_) => Ok(Outcome::Data(0)),
        // The handler's verdict for a signature that does not verify.
        Err(e) if e == CaliptraError::RUNTIME_MAILBOX_SIGNATURE_MISMATCH => Ok(Outcome::False),
        // A public key that is not on the curve (or other bad operands) is an invalid signature.
        Err(_) => Ok(Outcome::False),
    }
}
