// Licensed under the Apache-2.0 license

//! Signature checks in the image verifier and in the auth-manifest / debug-unlock code
//! (`verify_header` arms, `verify_lms_sig`, `process_image_metadata_col`, `validate_debug_unlock_token`).
//! The `acvp` builds of those functions are the diffs listed in the ACVP analysis document.

use super::{invalid, read_array, Fields, Outcome};
use crate::set_auth_manifest::acvp_state::{EccWhich, LmsWhich, Which as MetaWhich};
use crate::Drivers;
use caliptra_api::mailbox::*;
use caliptra_common::verifier::{FirmwareImageVerificationEnv, ImageSource};
use caliptra_error::{CaliptraError, CaliptraResult};
use caliptra_image_types::{ImageEccPubKey, ImageEccSignature, ImageLmsPublicKey, ImageLmsSignature};
use caliptra_image_verify::ImageVerifier;
use caliptra_lms_types::{LmsPublicKey, LmsSignature};
use zerocopy::{FromBytes, IntoBytes};

fn verdict(valid: bool) -> Outcome {
    if valid {
        Outcome::Data(0)
    } else {
        Outcome::False
    }
}

fn words(bytes: &[u8; 48]) -> [u32; 12] {
    caliptra_drivers::Array4x12::from(*bytes).0
}

/// [qx][qy][r][s] then the message field (returned with its offset in the mailbox).
fn key_sig_msg<'a>(
    fields: &mut Fields<'a>,
) -> CaliptraResult<([u8; 48], [u8; 48], [u8; 48], [u8; 48], &'a [u8], usize)> {
    let qx: [u8; 48] = read_array(fields.next()?)?;
    let qy: [u8; 48] = read_array(fields.next()?)?;
    let r: [u8; 48] = read_array(fields.next()?)?;
    let s: [u8; 48] = read_array(fields.next()?)?;
    let (msg, off) = fields.next_at()?;
    Ok((qx, qy, r, s, msg, off))
}

/// Errors the ECC verification path returns for a signature, key or operand it rejects.
fn ecc_rejected(e: CaliptraError, is_owner: bool) -> bool {
    let rejected = if is_owner {
        [
            CaliptraError::IMAGE_VERIFIER_ERR_OWNER_ECC_SIGNATURE_INVALID,
            CaliptraError::IMAGE_VERIFIER_ERR_OWNER_ECC_PUB_KEY_INVALID_ARG,
            CaliptraError::IMAGE_VERIFIER_ERR_OWNER_ECC_SIGNATURE_INVALID_ARG,
            CaliptraError::IMAGE_VERIFIER_ERR_OWNER_ECC_VERIFY_FAILURE,
        ]
    } else {
        [
            CaliptraError::IMAGE_VERIFIER_ERR_VENDOR_ECC_SIGNATURE_INVALID,
            CaliptraError::IMAGE_VERIFIER_ERR_VENDOR_ECC_PUB_KEY_INVALID_ARG,
            CaliptraError::IMAGE_VERIFIER_ERR_VENDOR_ECC_SIGNATURE_INVALID_ARG,
            CaliptraError::IMAGE_VERIFIER_ERR_VENDOR_ECC_VERIFY_FAILURE,
        ]
    };
    rejected.contains(&e)
}

/// Runs `f` on an `ImageVerifier` whose image source is the request (the SHA accelerator reads the message
/// from the mailbox at the given offset, as it does for a firmware image).
fn with_verifier<R>(
    drivers: &mut Drivers,
    msg: &[u8],
    f: impl FnOnce(&mut ImageVerifier<&mut FirmwareImageVerificationEnv<'_, '_, '_>>) -> R,
) -> R {
    drivers.abr.with_mldsa87(|mut mldsa87| {
        let mut venv = FirmwareImageVerificationEnv {
            sha256: &mut drivers.sha256,
            sha2_512_384: &mut drivers.sha2_512_384,
            sha2_512_384_acc: &mut drivers.sha2_512_384_acc,
            soc_ifc: &mut drivers.soc_ifc,
            ecc384: &mut drivers.ecc384,
            mldsa87: &mut mldsa87,
            data_vault: &drivers.persistent_data.get().rom.data_vault,
            pcr_bank: &mut drivers.pcr_bank,
            image_source: ImageSource::MboxMemory(msg),
            persistent_data: drivers.persistent_data.get(),
        };
        let mut verifier = ImageVerifier::new(&mut venv);
        f(&mut verifier)
    })
}

/// `verify_header` arms: hash the message with the accelerator digest, then `verify_ecc_sig`.
pub(crate) fn header_ecc(
    drivers: &mut Drivers,
    target: u32,
    fields: &mut Fields,
) -> CaliptraResult<Outcome> {
    let is_owner = target == ACVP_TARGET_HEADER_OWNER_ECC;
    let (qx, qy, r, s, msg, off) = key_sig_msg(fields)?;
    let key = ImageEccPubKey {
        x: words(&qx),
        y: words(&qy),
    };
    let sig = ImageEccSignature {
        r: words(&r),
        s: words(&s),
    };
    let result = with_verifier(drivers, msg, |v| {
        v.acvp_verify_ecc_sig(off as u32, msg.len() as u32, &key, &sig, is_owner)
    });
    match result {
        Ok(()) => Ok(verdict(true)),
        Err(e) if ecc_rejected(e, is_owner) => Ok(verdict(false)),
        Err(e) => Err(e),
    }
}

/// `verify_lms_sig` (vendor arm): the 48-byte message is the function's digest input, so it is passed in as
/// given and the LMS signature is over those bytes (a standard LMS vector).
pub(crate) fn header_lms(drivers: &mut Drivers, fields: &mut Fields) -> CaliptraResult<Outcome> {
    let pk: [u8; 48] = read_array(fields.next()?)?;
    let sig: [u8; 1620] = read_array(fields.next()?)?;
    let msg: [u8; 48] = read_array(fields.next()?)?;
    let pk: ImageLmsPublicKey = LmsPublicKey::<6>::read_from_bytes(&pk).map_err(|_| invalid())?;
    let sig: ImageLmsSignature =
        LmsSignature::<6, 51, 15>::read_from_bytes(&sig).map_err(|_| invalid())?;
    // ImageDigest384 holds the digest as big-endian words.
    let mut digest = [0u32; 12];
    for (word, chunk) in digest.iter_mut().zip(msg.chunks_exact(4)) {
        *word = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
    let result = with_verifier(drivers, &[], |v| {
        v.acvp_verify_lms_sig(&digest, &pk, &sig, false)
    });
    match result {
        Ok(()) => Ok(verdict(true)),
        Err(e)
            if e == CaliptraError::IMAGE_VERIFIER_ERR_VENDOR_LMS_SIGNATURE_INVALID
                || e == CaliptraError::IMAGE_VERIFIER_ERR_VENDOR_LMS_VERIFY_FAILURE =>
        {
            Ok(verdict(false))
        }
        Err(e) => Err(e),
    }
}

/// `process_image_metadata_col`, vendor or owner arm, ECC leg.
pub(crate) fn metadata_ecc(
    drivers: &mut Drivers,
    target: u32,
    fields: &mut Fields,
) -> CaliptraResult<Outcome> {
    let which = if target == ACVP_TARGET_METADATA_VENDOR_ECC {
        MetaWhich::Vendor
    } else {
        MetaWhich::Owner
    };
    let (qx, qy, r, s, msg, _) = key_sig_msg(fields)?;
    let ok = crate::SetAuthManifestCmd::acvp_metadata_col_ecc_leg(drivers, which, &qx, &qy, &r, &s, msg)?;
    Ok(verdict(ok))
}

/// `validate_debug_unlock_token` on the lab's message. The request, challenge and token are built to be
/// consistent with each other so the function's own consistency checks pass; the lab's message travels in the
/// token's ML-DSA public key field as [len u32 LE][bytes] (see the [ACVP patch] in `common/src/debug_unlock.rs`).
pub(crate) fn debug_unlock_token(
    drivers: &mut Drivers,
    fields: &mut Fields,
) -> CaliptraResult<Outcome> {
    let (qx, qy, r, s, msg, _) = key_sig_msg(fields)?;
    let mut token = ProductionAuthDebugUnlockToken {
        unlock_level: 1,
        ..Default::default()
    };
    token.length = ((core::mem::size_of::<ProductionAuthDebugUnlockToken>()
        - core::mem::size_of::<MailboxReqHeader>())
        / 4) as u32;
    token.ecc_public_key[..12].copy_from_slice(&words(&qx));
    token.ecc_public_key[12..].copy_from_slice(&words(&qy));
    token.ecc_signature[..12].copy_from_slice(&words(&r));
    token.ecc_signature[12..].copy_from_slice(&words(&s));
    {
        let carrier = token.mldsa_public_key.as_mut_bytes();
        carrier
            .get_mut(..4)
            .ok_or_else(invalid)?
            .copy_from_slice(&(msg.len() as u32).to_le_bytes());
        let dst = carrier
            .get_mut(4..4 + msg.len())
            .ok_or_else(invalid)?;
        for (d, b) in dst.iter_mut().zip(msg.iter()) {
            // SAFETY: `b` is a reference into the request field; a byte read is always aligned.
            *d = unsafe { core::ptr::read_volatile(b) };
        }
    }
    let request = ProductionAuthDebugUnlockReq {
        unlock_level: token.unlock_level,
        ..Default::default()
    };
    let challenge = ProductionAuthDebugUnlockChallenge::default();

    let result = drivers.abr.with_mldsa87(|mut mldsa87| {
        caliptra_common::debug_unlock::validate_debug_unlock_token(
            &drivers.soc_ifc,
            &mut drivers.sha2_512_384,
            &mut drivers.ecc384,
            &mut mldsa87,
            &mut drivers.dma,
            &request,
            &challenge,
            &token,
        )
    });
    match result {
        Ok(()) => Ok(verdict(true)),
        Err(e) if e == CaliptraError::SS_DBG_UNLOCK_PROD_INVALID_TOKEN_INVALID_SIGNATURE => {
            Ok(verdict(false))
        }
        // The ECC driver (error group 0x0005) rejects a key or signature scalar that is out of range or a
        // point that is not on the curve: an invalid signature, not a failure of the test.
        Err(e) if u32::from(e) >> 16 == 0x0005 => Ok(verdict(false)),
        Err(e) => Err(e),
    }
}

/// LMS legs of the auth-manifest verifiers: the 48-byte message is the digest for the LMS leg.
pub(crate) fn manifest_lms_leg(
    drivers: &mut Drivers,
    target: u32,
    fields: &mut Fields,
) -> CaliptraResult<Outcome> {
    let which = match target {
        ACVP_TARGET_LMS_VENDOR_SIGNED_DATA => LmsWhich::VendorSignedData,
        ACVP_TARGET_LMS_OWNER_PUB_KEYS => LmsWhich::OwnerPubKeys,
        ACVP_TARGET_LMS_VENDOR_METADATA => LmsWhich::VendorMetadataCol,
        ACVP_TARGET_LMS_OWNER_METADATA => LmsWhich::OwnerMetadataCol,
        _ => return Err(invalid()),
    };
    let pk: [u8; 48] = read_array(fields.next()?)?;
    let sig: [u8; 1620] = read_array(fields.next()?)?;
    let msg: [u8; 48] = read_array(fields.next()?)?;
    let ok = crate::SetAuthManifestCmd::acvp_lms_leg(drivers, which, &pk, &sig, &msg)?;
    Ok(verdict(ok))
}

/// ECC legs of `verify_vendor_signed_data` / `verify_owner_pub_keys` on the lab's message.
pub(crate) fn manifest_ecc_leg(
    drivers: &mut Drivers,
    target: u32,
    fields: &mut Fields,
) -> CaliptraResult<Outcome> {
    let which = if target == ACVP_TARGET_AUTHMAN_VENDOR_SIGNED_DATA_ECC {
        EccWhich::VendorSignedData
    } else {
        EccWhich::OwnerPubKeys
    };
    let (qx, qy, r, s, msg, _) = key_sig_msg(fields)?;
    let ok = crate::SetAuthManifestCmd::acvp_ecc_leg(drivers, which, &qx, &qy, &r, &s, msg)?;
    Ok(verdict(ok))
}
