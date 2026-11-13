// Licensed under the Apache-2.0 license

//! KDF targets: the counter-mode KDFs with a CMAC or HMAC PRF.

use super::{emit, invalid, read_array, Fields, Outcome};
use crate::Drivers;
use caliptra_drivers::{
    cmac_kdf, hmac_kdf, AesKey, Array4x12, Array4x16, HmacKey, HmacMode, HmacTag, LEArray4x8,
};
use caliptra_error::CaliptraResult;
use zerocopy::{transmute, IntoBytes};

/// `cmac_kdf` with an AES-256 key: output = CMAC(key, BE32(i) || label) for i in 1..=rounds.
pub(crate) fn cmac_kdf_target(
    drivers: &mut Drivers,
    fields: &mut Fields,
    out: &mut [u8],
) -> CaliptraResult<Outcome> {
    let key: [u8; 32] = read_array(fields.next()?)?;
    let key: LEArray4x8 = transmute!(key);
    let label = fields.next()?;
    let rounds = fields.next_u32()?;
    let output = cmac_kdf(&mut drivers.aes, AesKey::Array(&key), label, None, rounds)?;
    let n = (rounds as usize).checked_mul(16).ok_or_else(invalid)?;
    emit(out, output.as_bytes().get(..n).ok_or_else(invalid)?)
}

/// `hmac_kdf`: a single PRF block, HMAC(key, BE32(1) || label), with a raw key.
pub(crate) fn hmac_kdf_target(
    drivers: &mut Drivers,
    fields: &mut Fields,
    out: &mut [u8],
) -> CaliptraResult<Outcome> {
    let mode = fields.next_u32()?;
    let key = fields.next()?;
    let label = fields.next()?;
    match mode {
        384 => {
            let key = Array4x12::from(read_array::<48>(key)?);
            let mut tag = Array4x12::default();
            hmac_kdf(
                &mut drivers.hmac,
                HmacKey::Array4x12(&key),
                label,
                None,
                &mut drivers.trng,
                HmacTag::Array4x12(&mut tag),
                HmacMode::Hmac384,
            )?;
            emit(out, &<[u8; 48]>::from(tag))
        }
        512 => {
            let key = Array4x16::from(read_array::<64>(key)?);
            let mut tag = Array4x16::default();
            hmac_kdf(
                &mut drivers.hmac,
                HmacKey::Array4x16(&key),
                label,
                None,
                &mut drivers.trng,
                HmacTag::Array4x16(&mut tag),
                HmacMode::Hmac512,
            )?;
            emit(out, &<[u8; 64]>::from(tag))
        }
        _ => Err(invalid()),
    }
}
