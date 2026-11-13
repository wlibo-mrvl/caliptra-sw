// Licensed under the Apache-2.0 license

//! SHA-256 family and SHA-384/512 targets.

use super::{emit, invalid, Fields, Outcome};
use crate::Drivers;
use caliptra_drivers::{Sha256Alg, Sha256DigestOp};
use caliptra_error::CaliptraResult;

const SHA256_BLOCK_BYTES: usize = 64;

pub(crate) fn sha256_digest(
    drivers: &mut Drivers,
    fields: &mut Fields,
    out: &mut [u8],
) -> CaliptraResult<Outcome> {
    let msg = fields.next()?;
    let digest = drivers.sha256.digest(msg)?;
    emit(out, &<[u8; 32]>::from(digest))
}

pub(crate) fn sha256_digest_init(
    drivers: &mut Drivers,
    fields: &mut Fields,
    out: &mut [u8],
) -> CaliptraResult<Outcome> {
    let chunk = fields.next_u32()? as usize;
    let msg = fields.next()?;
    if chunk == 0 {
        return Err(invalid());
    }
    let mut op = drivers.sha256.digest_init()?;
    for piece in msg.chunks(chunk) {
        op.update(piece)?;
    }
    let mut digest = Default::default();
    op.finalize(&mut digest)?;
    emit(out, &<[u8; 32]>::from(digest))
}

/// Largest message `sha256_blocks_raw` accepts (the word buffer lives on the stack).
const BLOCKS_RAW_MAX_BYTES: usize = 8192;

/// `digest_blocks_raw` writes the caller's `[u32; 16]` blocks to the hash block register as
/// they are, with no byte swap (the ROM integrity check relies on that). The register takes
/// big-endian words, so the message bytes are loaded into words with `from_be_bytes`; the
/// digest is then SHA-256 of the message bytes.
pub(crate) fn sha256_blocks_raw(
    drivers: &mut Drivers,
    fields: &mut Fields,
    out: &mut [u8],
) -> CaliptraResult<Outcome> {
    let msg = fields.next()?;
    if msg.len() % SHA256_BLOCK_BYTES != 0 || msg.len() > BLOCKS_RAW_MAX_BYTES {
        return Err(invalid());
    }
    let mut words = [0u32; BLOCKS_RAW_MAX_BYTES / 4];
    for (w, chunk) in words.iter_mut().zip(msg.chunks_exact(4)) {
        let bytes: [u8; 4] = chunk.try_into().map_err(|_| invalid())?;
        *w = u32::from_be_bytes(bytes);
    }
    let n_blocks = msg.len() / SHA256_BLOCK_BYTES;
    // SAFETY: `words` is a local array of u32 (so 4-byte aligned) holding at least
    // `n_blocks * 16` words, so `n_blocks` reads of a `[u32; 16]` from its start are in bounds.
    let digest = unsafe {
        drivers
            .sha256
            .digest_blocks_raw(words.as_ptr() as *const [u32; 16], n_blocks)?
    };
    emit(out, &<[u8; 32]>::from(digest))
}

pub(crate) fn sha256_wntz(
    drivers: &mut Drivers,
    fields: &mut Fields,
    out: &mut [u8],
) -> CaliptraResult<Outcome> {
    let w = u8::try_from(fields.next_u32()?).map_err(|_| invalid())?;
    let n_mode = fields.next_u32()? != 0;
    let msg = fields.next()?;
    let mut op = drivers.sha256.digest_init()?;
    op.update_wntz(msg, w, n_mode)?;
    let mut digest = Default::default();
    op.finalize_wntz(&mut digest, w, n_mode)?;
    emit(out, &<[u8; 32]>::from(digest))
}

pub(crate) fn sha384_digest(
    drivers: &mut Drivers,
    fields: &mut Fields,
    out: &mut [u8],
) -> CaliptraResult<Outcome> {
    let msg = fields.next()?;
    let digest = drivers.sha2_512_384.sha384_digest(msg)?;
    emit(out, &<[u8; 48]>::from(digest))
}

pub(crate) fn sha512_digest(
    drivers: &mut Drivers,
    fields: &mut Fields,
    out: &mut [u8],
) -> CaliptraResult<Outcome> {
    let msg = fields.next()?;
    let digest = drivers.sha2_512_384.sha512_digest(msg)?;
    emit(out, &<[u8; 64]>::from(digest))
}
