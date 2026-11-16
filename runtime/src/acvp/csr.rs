// Licensed under the Apache-2.0 license

//! CSR generators that sign with the Runtime alias key (`generate_attested_ecc_csr`,
//! `generate_rt_alias_ecc_csr`). An `acvp` build of those functions signs the message given here.

use super::{emit, invalid, Fields, Outcome};
use crate::attested_csr::{acvp_generate_rt_alias_ecc_csr, DevIdKeyType, MAX_CSR_SIZE};
use crate::Drivers;
use caliptra_api::mailbox::*;
use caliptra_error::CaliptraResult;

const MAX_MSG: usize = 512;

/// Fields: [message]. Response: qx || qy || (COSE_Sign1 | DER CSR).
pub(crate) fn sign(
    drivers: &mut Drivers,
    target: u32,
    fields: &mut Fields,
    out: &mut [u8],
) -> CaliptraResult<Outcome> {
    let msg = fields.next()?;
    if msg.len() > MAX_MSG {
        return Err(invalid());
    }
    let rt_pub_key = drivers.persistent_data.get().rom.fht.rt_dice_ecc_pub_key;
    let mut result = [0u8; 96 + MAX_CSR_SIZE];
    let blob_len = match target {
        ACVP_TARGET_ATTESTED_ECC_CSR => {
            let mut buf = [0u8; 1024];
            let rt_key_id = [0u8; 20];
            let mut payload = [0u8; MAX_MSG];
            copy_bytes(&mut payload[..msg.len()], msg);
            let n = DevIdKeyType::RtAlias.generate_attested_ecc_csr(
                drivers,
                &payload[..msg.len()],
                &rt_key_id,
                &mut buf,
            )?;
            result[96..96 + n].copy_from_slice(buf.get(..n).ok_or_else(invalid)?);
            n
        }
        ACVP_TARGET_RT_ALIAS_ECC_CSR => {
            let mut csr_buf = [0u8; MAX_CSR_SIZE];
            csr_buf[..4].copy_from_slice(&(msg.len() as u32).to_le_bytes());
            copy_bytes(&mut csr_buf[4..4 + msg.len()], msg);
            let n = acvp_generate_rt_alias_ecc_csr(drivers, &mut csr_buf)?;
            result[96..96 + n].copy_from_slice(csr_buf.get(..n).ok_or_else(invalid)?);
            n
        }
        _ => return Err(invalid()),
    };
    result[..48].copy_from_slice(&<[u8; 48]>::from(&rt_pub_key.x));
    result[48..96].copy_from_slice(&<[u8; 48]>::from(&rt_pub_key.y));
    emit(out, &result[..96 + blob_len])
}

/// Copies from the mailbox with byte loads (see `read_array`).
fn copy_bytes(dst: &mut [u8], src: &[u8]) {
    for (d, s) in dst.iter_mut().zip(src.iter()) {
        // SAFETY: `s` is a reference into the request field; a byte read is always aligned.
        *d = unsafe { core::ptr::read_volatile(s) };
    }
}
