// Licensed under the Apache-2.0 license

//! Post-quantum signature verification targets: LMS and ML-DSA-87.
//!
//! The answer is a verdict: `Outcome::Data(0)` means the signature is valid, `Outcome::False`
//! means it is not. A malformed LMS key or signature is reported as invalid, as in ACVP.

use super::{invalid, read_array, Fields, Outcome};
use crate::Drivers;
use caliptra_drivers::{
    LmsResult, Mldsa87Msg, Mldsa87Mu, Mldsa87PubKey, Mldsa87Result, Mldsa87Signature,
};
use caliptra_error::{CaliptraError, CaliptraResult};
use caliptra_lms_types::{LmsPublicKey, LmsSignature};
use caliptra_registers::abr::AbrReg;
use zerocopy::{transmute, FromBytes};

const MLDSA_PK_BYTES: usize = 2592;
const MLDSA_SIG_BYTES: usize = 4627;
const MLDSA_SIG_PADDED_BYTES: usize = 4628;

/// Errors the LMS driver raises for a key or signature it cannot parse.
const LMS_PARSE_ERRORS: [CaliptraError; 13] = [
    CaliptraError::DRIVER_LMS_INVALID_LMS_ALGO_TYPE,
    CaliptraError::DRIVER_LMS_INVALID_LMOTS_ALGO_TYPE,
    CaliptraError::DRIVER_LMS_INVALID_WINTERNITS_PARAM,
    CaliptraError::DRIVER_LMS_INVALID_PVALUE,
    CaliptraError::DRIVER_LMS_INVALID_HASH_WIDTH,
    CaliptraError::DRIVER_LMS_INVALID_TREE_HEIGHT,
    CaliptraError::DRIVER_LMS_INVALID_Q_VALUE,
    CaliptraError::DRIVER_LMS_INVALID_INDEX,
    CaliptraError::DRIVER_LMS_PATH_OUT_OF_BOUNDS,
    CaliptraError::DRIVER_LMS_INVALID_SIGNATURE_LENGTH,
    CaliptraError::DRIVER_LMS_INVALID_PUBLIC_KEY_LENGTH,
    CaliptraError::DRIVER_LMS_INVALID_SIGNATURE_DEPTH,
    CaliptraError::DRIVER_LMS_SIGNATURE_LMOTS_DOESNT_MATCH_PUBKEY_LMOTS,
];

fn verdict(valid: bool) -> Outcome {
    if valid {
        Outcome::Data(0)
    } else {
        Outcome::False
    }
}

pub(crate) fn lms_verify(
    drivers: &mut Drivers,
    fields: &mut Fields,
    _out: &mut [u8],
) -> CaliptraResult<Outcome> {
    // Copy the key and signature out of the mailbox byte by byte; they are big-endian
    // wire-format structs with no alignment requirement.
    let pk: [u8; 48] = read_array(fields.next()?)?;
    let sig: [u8; 1620] = read_array(fields.next()?)?;
    let msg = fields.next()?;
    let pk = LmsPublicKey::<6>::read_from_bytes(&pk).map_err(|_| invalid())?;
    let sig = LmsSignature::<6, 51, 15>::read_from_bytes(&sig).map_err(|_| invalid())?;
    match drivers
        .lms
        .verify_lms_signature(&mut drivers.sha256, msg, &pk, &sig)
    {
        Ok(LmsResult::Success) => Ok(verdict(true)),
        Ok(_) => Ok(verdict(false)),
        Err(e) if LMS_PARSE_ERRORS.contains(&e) => Ok(verdict(false)),
        Err(e) => Err(e),
    }
}

/// Reads the public key and the signature (4627 bytes, padded to the driver's 4628).
fn mldsa_key_and_sig(fields: &mut Fields) -> CaliptraResult<(Mldsa87PubKey, Mldsa87Signature)> {
    let pk: [u8; MLDSA_PK_BYTES] = read_array(fields.next()?)?;
    let sig_in: [u8; MLDSA_SIG_BYTES] = read_array(fields.next()?)?;
    let mut sig = [0u8; MLDSA_SIG_PADDED_BYTES];
    sig.get_mut(..MLDSA_SIG_BYTES)
        .ok_or_else(invalid)?
        .copy_from_slice(&sig_in);
    Ok((transmute!(pk), transmute!(sig)))
}

fn mldsa_verdict(result: Mldsa87Result) -> Outcome {
    verdict(result == Mldsa87Result::Success)
}

/// Largest context ML-DSA allows (it is carried in a one-byte length).
const MLDSA_CTX_MAX_BYTES: usize = 255;
/// Bound on the wait for the engine to become ready before the context is written.
const MLDSA_READY_POLLS: u32 = 1_000_000;

/// Programs the engine's context registers: size, then the context as little-endian dwords.
///
/// In streaming mode the controller builds M' = 0x00 || ctx_size || ctx || message itself
/// (`abr_ctrl.sv`, the stream message FSM). `Mldsa87::verify_var` has no context parameter, so the
/// registers are written before it is called; the engine clears them when the operation ends.
fn program_context(ctx: &[u8]) -> CaliptraResult<()> {
    if ctx.len() > MLDSA_CTX_MAX_BYTES {
        return Err(invalid());
    }
    // SAFETY: the register block is a memory-mapped singleton; this handle is used only here,
    // while no ML-DSA operation is in progress (the runtime is single threaded and the handler
    // has not started one), and `with_mldsa87` takes its own handle afterwards.
    let mut abr = unsafe { AbrReg::new() };
    let regs = abr.regs_mut();
    let mut polls = 0;
    while !regs.mldsa_status().read().ready() {
        polls += 1;
        if polls > MLDSA_READY_POLLS {
            return Err(CaliptraError::DRIVER_MLDSA87_HW_ERROR);
        }
    }
    regs.mldsa_ctx_config()
        .write(|w| w.ctx_size(ctx.len() as u32));
    for (i, chunk) in ctx.chunks(4).enumerate() {
        let mut word = [0u8; 4];
        word.get_mut(..chunk.len())
            .ok_or_else(invalid)?
            .copy_from_slice(chunk);
        regs.mldsa_ctx().at(i).write(|_| u32::from_le_bytes(word));
    }
    Ok(())
}

/// `Mldsa87::verify_var` streams the message; the context (possibly empty) comes from the registers.
pub(crate) fn mldsa_verify_var(
    drivers: &mut Drivers,
    fields: &mut Fields,
    _out: &mut [u8],
) -> CaliptraResult<Outcome> {
    let (pk, sig) = mldsa_key_and_sig(fields)?;
    let ctx = fields.next()?;
    let msg = fields.next()?;
    program_context(ctx)?;
    let result = drivers
        .abr
        .with_mldsa87(|mut m| m.verify_var(&pk, msg, &sig))?;
    Ok(mldsa_verdict(result))
}

/// `Mldsa87::verify`: the hardware prepends the two-byte domain prefix to the 64-byte message.
pub(crate) fn mldsa_verify_msg(
    drivers: &mut Drivers,
    fields: &mut Fields,
    _out: &mut [u8],
) -> CaliptraResult<Outcome> {
    let (pk, sig) = mldsa_key_and_sig(fields)?;
    let msg: [u8; 64] = read_array(fields.next()?)?;
    let msg: Mldsa87Msg = transmute!(msg);
    let result = drivers
        .abr
        .with_mldsa87(|mut m| m.verify(&pk, &msg, &sig))?;
    Ok(mldsa_verdict(result))
}

/// `Mldsa87::verify_external_mu`.
pub(crate) fn mldsa_verify_mu(
    drivers: &mut Drivers,
    fields: &mut Fields,
    _out: &mut [u8],
) -> CaliptraResult<Outcome> {
    let (pk, sig) = mldsa_key_and_sig(fields)?;
    let mu: [u8; 64] = read_array(fields.next()?)?;
    let mu: Mldsa87Mu = transmute!(mu);
    let result = drivers
        .abr
        .with_mldsa87(|mut m| m.verify_external_mu(&pk, &mu, &sig))?;
    Ok(mldsa_verdict(result))
}
