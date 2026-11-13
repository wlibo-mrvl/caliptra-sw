// Licensed under the Apache-2.0 license

//! HMAC targets: the one-shot `Hmac::hmac` and the streaming `hmac_init`/`update`/`finalize`.

use super::{emit, invalid, read_array, Fields, Outcome};
use crate::Drivers;
use caliptra_drivers::{Array4x12, Array4x16, HmacData, HmacKey, HmacMode, HmacTag};
use caliptra_error::CaliptraResult;

/// Runs HMAC with the given key and message; `streaming` selects `hmac_init` over `hmac`.
fn run(
    drivers: &mut Drivers,
    fields: &mut Fields,
    out: &mut [u8],
    streaming: bool,
) -> CaliptraResult<Outcome> {
    let mode = fields.next_u32()?;
    let key = fields.next()?;
    let msg = fields.next()?;
    match mode {
        384 => {
            let key: [u8; 48] = read_array(key)?;
            let key = Array4x12::from(key);
            let mut tag = Array4x12::default();
            if streaming {
                let mut op = drivers.hmac.hmac_init(
                    HmacKey::Array4x12(&key),
                    &mut drivers.trng,
                    HmacTag::Array4x12(&mut tag),
                    HmacMode::Hmac384,
                )?;
                op.update(msg)?;
                op.finalize()?;
            } else {
                drivers.hmac.hmac(
                    HmacKey::Array4x12(&key),
                    HmacData::Slice(msg),
                    &mut drivers.trng,
                    HmacTag::Array4x12(&mut tag),
                    HmacMode::Hmac384,
                )?;
            }
            emit(out, &<[u8; 48]>::from(tag))
        }
        512 => {
            let key: [u8; 64] = read_array(key)?;
            let key = Array4x16::from(key);
            let mut tag = Array4x16::default();
            if streaming {
                let mut op = drivers.hmac.hmac_init(
                    HmacKey::Array4x16(&key),
                    &mut drivers.trng,
                    HmacTag::Array4x16(&mut tag),
                    HmacMode::Hmac512,
                )?;
                op.update(msg)?;
                op.finalize()?;
            } else {
                drivers.hmac.hmac(
                    HmacKey::Array4x16(&key),
                    HmacData::Slice(msg),
                    &mut drivers.trng,
                    HmacTag::Array4x16(&mut tag),
                    HmacMode::Hmac512,
                )?;
            }
            emit(out, &<[u8; 64]>::from(tag))
        }
        _ => Err(invalid()),
    }
}

pub(crate) fn hmac(
    drivers: &mut Drivers,
    fields: &mut Fields,
    out: &mut [u8],
) -> CaliptraResult<Outcome> {
    run(drivers, fields, out, false)
}

pub(crate) fn hmac_init(
    drivers: &mut Drivers,
    fields: &mut Fields,
    out: &mut [u8],
) -> CaliptraResult<Outcome> {
    run(drivers, fields, out, true)
}
