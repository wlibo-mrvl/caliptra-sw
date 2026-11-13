// Licensed under the Apache-2.0 license

//! AES-256 CBC and CTR targets (raw key and IV, no key vault).

use super::{invalid, read_array, Fields, Outcome};
use crate::Drivers;
use caliptra_drivers::{AesKey, AesOperation, LEArray4x4, LEArray4x8, AES_BLOCK_SIZE_BYTES};
use caliptra_error::{CaliptraError, CaliptraResult};
use zerocopy::{transmute, IntoBytes};

fn key_and_iv(fields: &mut Fields) -> CaliptraResult<(LEArray4x8, LEArray4x4)> {
    let key: [u8; 32] = read_array(fields.next()?)?;
    let iv: [u8; 16] = read_array(fields.next()?)?;
    Ok((transmute!(key), transmute!(iv)))
}

pub(crate) fn aes_cbc(
    drivers: &mut Drivers,
    fields: &mut Fields,
    out: &mut [u8],
) -> CaliptraResult<Outcome> {
    let op = match fields.next_u32()? {
        1 => AesOperation::Encrypt,
        2 => AesOperation::Decrypt,
        _ => return Err(invalid()),
    };
    let (key, iv) = key_and_iv(fields)?;
    let data = fields.next()?;
    if data.len() % AES_BLOCK_SIZE_BYTES != 0 {
        return Err(invalid());
    }
    let dst = out
        .get_mut(..data.len())
        .ok_or(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)?;
    drivers.aes.aes_256_cbc(&key, &iv, op, data, dst)?;
    Ok(Outcome::Data(data.len()))
}

/// CTR encryption and decryption are the same operation.
pub(crate) fn aes_ctr(
    drivers: &mut Drivers,
    fields: &mut Fields,
    out: &mut [u8],
) -> CaliptraResult<Outcome> {
    let (key, iv) = key_and_iv(fields)?;
    let data = fields.next()?;
    let dst = out
        .get_mut(..data.len())
        .ok_or(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)?;
    drivers.aes.aes_256_ctr(&key, &iv, 0, data, dst)?;
    Ok(Outcome::Data(data.len()))
}

/// AES-256 CMAC (SP 800-38B) with a raw key.
pub(crate) fn aes_cmac(
    drivers: &mut Drivers,
    fields: &mut Fields,
    out: &mut [u8],
) -> CaliptraResult<Outcome> {
    let key: [u8; 32] = read_array(fields.next()?)?;
    let key: LEArray4x8 = transmute!(key);
    let msg = fields.next()?;
    let mac = drivers.aes.cmac(AesKey::Array(&key), msg)?;
    super::emit(out, mac.as_bytes())
}
