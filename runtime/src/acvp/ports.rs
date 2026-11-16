// Licensed under the Apache-2.0 license

//! ACVP test ports of ROM-only functions (`derive_stable_key`, `derive_hek`,
//! `hkdf_stable_owner_root_key`) and of the HPKE P-384 `derive_key_pair`.
//!
//! The ROM functions are not part of the Runtime image, and their inputs come from the key vault or
//! from constants, which a lab vector cannot supply. Each port below is a copy of the original with the
//! key-vault slots replaced by arrays and the fixed labels replaced by request fields; the crypto calls
//! that remain (`Crypto::encrypt_cmk`, `Hmac::hmac`, `hmac_kdf`, `hkdf_extract`, `hkdf_expand`) are the
//! shared driver functions the originals call. The diff against each original is for atsec to review.

use super::{emit, invalid, read_array, Fields, Outcome};
use crate::Drivers;
use caliptra_api::mailbox::*;
use caliptra_common::crypto::{Crypto, UnencryptedCmk};
use caliptra_drivers::{
    hkdf_expand, hkdf_extract, hmac_kdf, Array4x12, Array4x16, HmacData, HmacKey, HmacMode, HmacTag,
    LEArray4x8,
};
use caliptra_error::CaliptraResult;
use zerocopy::{transmute, FromBytes, IntoBytes};

/// ROM `derive_stable_key`, from the point where the 80-byte `UnencryptedCmk` exists: draw the IV from
/// the TRNG the same way (`trng.generate()`, first three words) and call `Crypto::encrypt_cmk` with the
/// KEK. The KEK is the vector key (second share zero) instead of `Crypto::get_cmb_aes_key`, and the
/// plaintext is the vector's 80 bytes instead of the output of `cmac_kdf` + `hmac_kdf` (those two steps
/// are covered by the ROM `cmac_kdf` and `hmac_kdf` entries). Returns iv(12) || ciphertext(80) || tag(16).
pub(crate) fn derive_stable_key(
    drivers: &mut Drivers,
    fields: &mut Fields,
    out: &mut [u8],
) -> CaliptraResult<Outcome> {
    let key_bytes: [u8; 32] = read_array(fields.next()?)?;
    let key: LEArray4x8 = transmute!(key_bytes);
    let pt: [u8; 80] = read_array(fields.next()?)?;
    let unencrypted_cmk = UnencryptedCmk::read_from_bytes(&pt[..]).map_err(|_| invalid())?;

    let random = drivers.trng.generate()?;
    let kek_iv: [u32; 3] = [random.0[0], random.0[1], random.0[2]];
    let e = Crypto::encrypt_cmk(
        &mut drivers.aes,
        &mut drivers.trng,
        &unencrypted_cmk,
        kek_iv.into(),
        (key, LEArray4x8::default()),
    )?;

    let (iv, ct, tag) = (e.iv.as_bytes(), &e.ciphertext[..], e.gcm_tag.as_bytes());
    let total = iv.len() + ct.len() + tag.len();
    let dst = out
        .get_mut(..total)
        .ok_or(caliptra_error::CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)?;
    dst[..iv.len()].copy_from_slice(iv);
    dst[iv.len()..iv.len() + ct.len()].copy_from_slice(ct);
    dst[iv.len() + ct.len()..].copy_from_slice(tag);
    Ok(Outcome::Data(total))
}

/// A salt of up to one block (a vector gives a block-sized, all-zero "default" salt). The driver takes
/// keys of at most `max` bytes; HMAC zero-pads a short key to the block size, so trailing zero bytes
/// beyond `max` do not change the result and are accepted, anything else is not.
fn salt_up_to<const N: usize>(salt: &[u8]) -> CaliptraResult<[u8; N]> {
    let mut padded = [0u8; N];
    for (i, b) in salt.iter().enumerate() {
        // SAFETY: `b` is a reference into the request field; a byte read is always aligned.
        let v = unsafe { core::ptr::read_volatile(b) };
        match padded.get_mut(i) {
            Some(slot) => *slot = v,
            None if v != 0 => return Err(invalid()),
            None => {}
        }
    }
    Ok(padded)
}

/// ROM `derive_hek` / `hkdf_stable_owner_root_key`: HKDF-Extract-like `HMAC-SHA-512(key = salt, data = z)`
/// gives the PRK, then `hmac_kdf(key = PRK, label)` gives the output. The originals take the salt (CDI or a
/// fixed domain string) and the data (HEK seed) from the key vault and use a constant label
/// (`ocp_lock_hek`, `STABLE_OWNER_ROOT_KEY_LABEL`); here all three are request fields.
/// Returns the 64-byte output.
pub(crate) fn twostep_sha512(
    drivers: &mut Drivers,
    _target: u32,
    fields: &mut Fields,
    out: &mut [u8],
) -> CaliptraResult<Outcome> {
    let salt = salt_up_to::<64>(fields.next()?)?;
    let z = fields.next()?;
    let label = fields.next()?;
    let salt = Array4x16::from(salt);
    let mut prk = Array4x16::default();
    drivers.hmac.hmac(
        HmacKey::Array4x16(&salt),
        HmacData::Slice(z),
        &mut drivers.trng,
        HmacTag::Array4x16(&mut prk),
        HmacMode::Hmac512,
    )?;
    let mut okm = Array4x16::default();
    hmac_kdf(
        &mut drivers.hmac,
        HmacKey::Array4x16(&prk),
        label,
        None,
        &mut drivers.trng,
        HmacTag::Array4x16(&mut okm),
        HmacMode::Hmac512,
    )?;
    emit(out, &<[u8; 64]>::from(okm))
}

/// HPKE P-384 `derive_key_pair` (drivers/src/hpke/kem/p384.rs): the original runs a labeled HKDF-Extract
/// over the 48-byte IKM, a labeled HKDF-Expand for 48 bytes, then derives the ECDH key pair from that
/// output. This port runs the same two HKDF-SHA-384 steps over the vector's inputs (salt, z, fixed info,
/// no HPKE labels) and returns the 48-byte output (`dkm`); the key pair step is left out.
pub(crate) fn derive_key_pair(
    drivers: &mut Drivers,
    fields: &mut Fields,
    out: &mut [u8],
) -> CaliptraResult<Outcome> {
    let salt = salt_up_to::<48>(fields.next()?)?;
    let z = fields.next()?;
    let info = fields.next()?;
    let mut prk = Array4x12::default();
    hkdf_extract(
        &mut drivers.hmac,
        z,
        &salt,
        &mut drivers.trng,
        HmacTag::Array4x12(&mut prk),
        HmacMode::Hmac384,
    )?;
    let mut okm = Array4x12::default();
    hkdf_expand(
        &mut drivers.hmac,
        HmacKey::Array4x12(&prk),
        info,
        &mut drivers.trng,
        HmacTag::Array4x12(&mut okm),
        HmacMode::Hmac384,
    )?;
    emit(out, &<[u8; 48]>::from(okm))
}
