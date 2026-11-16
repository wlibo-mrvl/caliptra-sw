// Licensed under the Apache-2.0 license

/*++

File Name:

    mod.rs

Abstract:

    Test-only `ACVP_TEST` mailbox command. Dispatches by target id to a driver function
    and returns the raw result in one round trip. Built only with the `acvp` feature.

    Request:  [chksum u32][target u32][n_fields u32] then n_fields x [len u32][bytes, padded to 4].
    Response: [chksum u32][fips_status u32][result u32][err_code u32][data_len u32][data].

--*/

use crate::Drivers;
use caliptra_api::mailbox::*;
use caliptra_error::{CaliptraError, CaliptraResult};

mod aes;
mod cm;
mod csr;
mod ecdsa;
mod hmac;
mod kdf;
mod ports;
mod verify;
mod pqc;
mod sha;

/// What a target handler produced.
pub(crate) enum Outcome {
    /// The operation succeeded; this many bytes of result are in the output buffer.
    Data(usize),
    /// The operation completed and the answer is "no" (e.g. signature verification failed).
    False,
}

/// Zero-copy reader over the fields of a request.
pub(crate) struct Fields<'a> {
    data: &'a [u8],
    off: usize,
    left: u32,
}

pub(crate) fn invalid() -> CaliptraError {
    CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS
}

fn read_u32(data: &[u8], off: usize) -> CaliptraResult<u32> {
    let end = off.checked_add(4).ok_or_else(invalid)?;
    let bytes: [u8; 4] = data
        .get(off..end)
        .ok_or_else(invalid)?
        .try_into()
        .map_err(|_| invalid())?;
    Ok(u32::from_le_bytes(bytes))
}

impl<'a> Fields<'a> {
    /// Parses the request header and returns the target id and a reader for the fields.
    fn parse(cmd_bytes: &'a [u8]) -> CaliptraResult<(u32, Self)> {
        if cmd_bytes.len() < ACVP_REQ_HDR_SIZE {
            return Err(invalid());
        }
        // cmd_bytes[0..4] is the checksum, already verified by the mailbox layer.
        let target = read_u32(cmd_bytes, 4)?;
        let left = read_u32(cmd_bytes, 8)?;
        Ok((
            target,
            Self {
                data: cmd_bytes,
                off: ACVP_REQ_HDR_SIZE,
                left,
            },
        ))
    }

    /// Returns the next field's bytes (without padding).
    pub(crate) fn next(&mut self) -> CaliptraResult<&'a [u8]> {
        if self.left == 0 {
            return Err(invalid());
        }
        let len = read_u32(self.data, self.off)? as usize;
        let start = self.off.checked_add(4).ok_or_else(invalid)?;
        let end = start.checked_add(len).ok_or_else(invalid)?;
        let field = self.data.get(start..end).ok_or_else(invalid)?;
        let padded = len.checked_add(3).ok_or_else(invalid)? & !3usize;
        self.off = start.checked_add(padded).ok_or_else(invalid)?;
        self.left -= 1;
        Ok(field)
    }

    /// Like `next`, and also returns the byte offset of the field's data within the request
    /// (the mailbox contents), for hardware that reads the mailbox itself.
    pub(crate) fn next_at(&mut self) -> CaliptraResult<(&'a [u8], usize)> {
        let start = self.off.checked_add(4).ok_or_else(invalid)?;
        Ok((self.next()?, start))
    }

    /// Returns the next field as a little-endian u32.
    pub(crate) fn next_u32(&mut self) -> CaliptraResult<u32> {
        read_u32(self.next()?, 0)
    }
}

/// Copies a fixed-size field out of the mailbox with byte loads.
///
/// The mailbox is memory-mapped and does not tolerate misaligned word loads. For a small
/// constant length the compiler expands a plain copy into overlapping `lw` loads at odd
/// offsets, which fault, so the bytes are read one at a time with volatile loads that
/// cannot be merged.
pub(crate) fn read_array<const N: usize>(src: &[u8]) -> CaliptraResult<[u8; N]> {
    if src.len() != N {
        return Err(invalid());
    }
    let mut dst = [0u8; N];
    for (d, s) in dst.iter_mut().zip(src.iter()) {
        // SAFETY: `s` is a reference into `src`, so it is valid and aligned for a u8 read.
        *d = unsafe { core::ptr::read_volatile(s) };
    }
    Ok(dst)
}

/// Copies `src` to the start of `out` and returns `Outcome::Data(src.len())`.
pub(crate) fn emit(out: &mut [u8], src: &[u8]) -> CaliptraResult<Outcome> {
    out.get_mut(..src.len())
        .ok_or(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)?
        .copy_from_slice(src);
    Ok(Outcome::Data(src.len()))
}

fn dispatch(
    drivers: &mut Drivers,
    target: u32,
    fields: &mut Fields,
    out: &mut [u8],
) -> CaliptraResult<Outcome> {
    match target {
        // Echoes the first field. Used to check the wire format and the mailbox size limits.
        ACVP_TARGET_PING => emit(out, fields.next()?),
        ACVP_TARGET_SHA256_DIGEST => sha::sha256_digest(drivers, fields, out),
        ACVP_TARGET_SHA256_DIGEST_INIT => sha::sha256_digest_init(drivers, fields, out),
        ACVP_TARGET_SHA256_BLOCKS_RAW => sha::sha256_blocks_raw(drivers, fields, out),
        ACVP_TARGET_SHA256_WNTZ => sha::sha256_wntz(drivers, fields, out),
        ACVP_TARGET_SHA384_DIGEST => sha::sha384_digest(drivers, fields, out),
        ACVP_TARGET_SHA512_DIGEST => sha::sha512_digest(drivers, fields, out),
        ACVP_TARGET_SHA384_IMAGE => sha::sha384_image(drivers, fields, out),
        ACVP_TARGET_HMAC => hmac::hmac(drivers, fields, out),
        ACVP_TARGET_HMAC_INIT => hmac::hmac_init(drivers, fields, out),
        ACVP_TARGET_AES_CBC => aes::aes_cbc(drivers, fields, out),
        ACVP_TARGET_AES_CTR => aes::aes_ctr(drivers, fields, out),
        ACVP_TARGET_AES_CMAC => aes::aes_cmac(drivers, fields, out),
        ACVP_TARGET_CMAC_KDF => kdf::cmac_kdf_target(drivers, fields, out),
        ACVP_TARGET_HMAC_KDF => kdf::hmac_kdf_target(drivers, fields, out),
        ACVP_TARGET_LMS_VERIFY => pqc::lms_verify(drivers, fields, out),
        ACVP_TARGET_MLDSA_VERIFY_VAR => pqc::mldsa_verify_var(drivers, fields, out),
        ACVP_TARGET_MLDSA_VERIFY_MSG => pqc::mldsa_verify_msg(drivers, fields, out),
        ACVP_TARGET_MLDSA_VERIFY_MU => pqc::mldsa_verify_mu(drivers, fields, out),
        ACVP_TARGET_ECDSA384_VERIFY => ecdsa::ecdsa384_verify(drivers, fields, out),
        ACVP_TARGET_ECDSA384_SIGN => ecdsa::ecdsa384_sign(drivers, fields, out),
        ACVP_TARGET_CM_ENCRYPT_CMK
        | ACVP_TARGET_CM_ENCRYPT_AES_CONTEXT
        | ACVP_TARGET_CM_ENCRYPT_AES_GCM_CONTEXT
        | ACVP_TARGET_CM_ENCRYPT_ECDH_CONTEXT
        | ACVP_TARGET_CM_ENCRYPT_SHAKE256_CONTEXT => cm::encrypt(drivers, target, fields, out),
        ACVP_TARGET_PORT_DERIVE_STABLE_KEY => ports::derive_stable_key(drivers, fields, out),
        ACVP_TARGET_PORT_DERIVE_HEK | ACVP_TARGET_PORT_HKDF_STABLE_OWNER_ROOT_KEY => {
            ports::twostep_sha512(drivers, target, fields, out)
        }
        ACVP_TARGET_PORT_DERIVE_KEY_PAIR => ports::derive_key_pair(drivers, fields, out),
        ACVP_TARGET_CM_ECDSA_VERIFY => cm::ecdsa_verify(drivers, fields),
        ACVP_TARGET_ATTESTED_ECC_CSR | ACVP_TARGET_RT_ALIAS_ECC_CSR => csr::sign(drivers, target, fields, out),
        ACVP_TARGET_HEADER_VENDOR_ECC | ACVP_TARGET_HEADER_OWNER_ECC => {
            verify::header_ecc(drivers, target, fields)
        }
        ACVP_TARGET_HEADER_LMS => verify::header_lms(drivers, fields),
        ACVP_TARGET_METADATA_VENDOR_ECC | ACVP_TARGET_METADATA_OWNER_ECC => {
            verify::metadata_ecc(drivers, target, fields)
        }
        ACVP_TARGET_DEBUG_UNLOCK_TOKEN => verify::debug_unlock_token(drivers, fields),
        ACVP_TARGET_AUTHMAN_VENDOR_SIGNED_DATA_ECC | ACVP_TARGET_AUTHMAN_OWNER_PUB_KEYS_ECC => {
            verify::manifest_ecc_leg(drivers, target, fields)
        }
        ACVP_TARGET_LMS_VENDOR_SIGNED_DATA
        | ACVP_TARGET_LMS_OWNER_PUB_KEYS
        | ACVP_TARGET_LMS_VENDOR_METADATA
        | ACVP_TARGET_LMS_OWNER_METADATA => verify::manifest_lms_leg(drivers, target, fields),
        _ => Err(CaliptraError::RUNTIME_UNIMPLEMENTED_COMMAND),
    }
}

pub(crate) fn execute(
    drivers: &mut Drivers,
    cmd_bytes: &[u8],
    resp: &mut [u8],
) -> CaliptraResult<usize> {
    let (target, mut fields) = Fields::parse(cmd_bytes)?;
    if resp.len() < ACVP_RESP_HDR_SIZE {
        return Err(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY);
    }
    let (hdr, out) = resp.split_at_mut(ACVP_RESP_HDR_SIZE);

    // A malformed request or an unknown target fails the mailbox command. A driver error
    // is reported in the response so the host can tell it apart from a verdict.
    let (result, err_code, len) = match dispatch(drivers, target, &mut fields, out) {
        Ok(Outcome::Data(n)) => (ACVP_RESULT_OK, 0, n),
        Ok(Outcome::False) => (ACVP_RESULT_FALSE, 0, 0),
        Err(e)
            if e == CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS
                || e == CaliptraError::RUNTIME_UNIMPLEMENTED_COMMAND =>
        {
            return Err(e)
        }
        Err(e) => (ACVP_RESULT_ERROR, u32::from(e), 0),
    };

    // hdr[0..8] is the mailbox response header, filled in by the caller.
    let fields_out = hdr
        .get_mut(8..)
        .ok_or(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)?;
    let words = [result, err_code, len as u32];
    for (chunk, word) in fields_out.chunks_exact_mut(4).zip(words) {
        chunk.copy_from_slice(&word.to_le_bytes());
    }
    Ok(ACVP_RESP_HDR_SIZE + len)
}
