// Licensed under the Apache-2.0 license

//! ECDSA P-384 / SHA-384 targets using the ROM/FMC helpers in `caliptra_common::crypto`.

use super::{emit, invalid, read_array, Fields, Outcome};
use crate::dpe_crypto::DpeCrypto;
use crate::Drivers;
use caliptra_dpe_crypto::{
    ecdsa::{curve_384::EcdsaPub384, EcdsaPubKey, EcdsaSig, EcdsaSignature},
    PubKey, SignData, Signature,
};
use caliptra_common::crypto::Crypto;
use caliptra_common::keyids::KEY_ID_TMP;
use caliptra_drivers::{
    Array4x12, Ecc384PrivKeyOut, Ecc384PubKey, Ecc384Result, Ecc384Seed, Ecc384Signature, KeyUsage,
    KeyWriteArgs,
};
use caliptra_error::{CaliptraError, CaliptraResult};

fn scalar(bytes: &[u8]) -> CaliptraResult<Array4x12> {
    Ok(Array4x12::from(read_array::<48>(bytes)?))
}

/// Verifies a signature over `msg` (hashed with SHA-384 inside the helper).
pub(crate) fn ecdsa384_verify(
    drivers: &mut Drivers,
    fields: &mut Fields,
    _out: &mut [u8],
) -> CaliptraResult<Outcome> {
    let pub_key = Ecc384PubKey {
        x: scalar(fields.next()?)?,
        y: scalar(fields.next()?)?,
    };
    let sig = Ecc384Signature {
        r: scalar(fields.next()?)?,
        s: scalar(fields.next()?)?,
    };
    let msg = fields.next()?;
    // A zero r or s can never be valid (the image verifier rejects them before the engine).
    if sig.r == Array4x12::default() || sig.s == Array4x12::default() {
        return Ok(Outcome::False);
    }
    match Crypto::ecdsa384_verify(
        &mut drivers.sha2_512_384,
        &mut drivers.ecc384,
        &pub_key,
        msg,
        &sig,
    ) {
        Ok(Ecc384Result::Success) => Ok(Outcome::Data(0)),
        Ok(_) => Ok(Outcome::False),
        // A public key that is not on the curve (or other bad operands) is an invalid signature.
        Err(_) => Ok(Outcome::False),
    }
}

/// Runs `DpeCrypto::sign_ec` with the temporary key-vault key.
fn dpe_sign_ec(
    drivers: &mut Drivers,
    pub_key: &Ecc384PubKey,
    msg: &[u8],
) -> CaliptraResult<Ecc384Signature> {
    let dpe_pub = PubKey::Ecdsa(EcdsaPubKey::Ecdsa384(EcdsaPub384 {
        x: <[u8; 48]>::from(&pub_key.x),
        y: <[u8; 48]>::from(&pub_key.y),
    }));
    let sig = DpeCrypto::sign_ec(
        &mut drivers.ecc384,
        &mut drivers.sha2_512_384,
        &mut drivers.trng,
        &SignData::Raw(msg),
        &KEY_ID_TMP,
        &dpe_pub,
    )
    .map_err(|_| CaliptraError::RUNTIME_INTERNAL)?;
    let Signature::Ecdsa(EcdsaSignature::Ecdsa384(EcdsaSig { r, s })) = sig else {
        return Err(CaliptraError::RUNTIME_INTERNAL);
    };
    Ok(Ecc384Signature {
        r: Array4x12::from(r),
        s: Array4x12::from(s),
    })
}

/// Derives a key pair from a seed into a key-vault slot, signs `msg`, erases the slot, and
/// returns qx || qy || r || s.
pub(crate) fn ecdsa384_sign(
    drivers: &mut Drivers,
    fields: &mut Fields,
    out: &mut [u8],
) -> CaliptraResult<Outcome> {
    let variant = fields.next_u32()?;
    let seed = scalar(fields.next()?)?;
    let msg = fields.next()?;
    if variant > 2 {
        return Err(invalid());
    }

    let pub_key = drivers.ecc384.key_pair(
        Ecc384Seed::Array4x12(&seed),
        &Array4x12::default(),
        &mut drivers.trng,
        Ecc384PrivKeyOut::Key(KeyWriteArgs::new(
            KEY_ID_TMP,
            KeyUsage::default().set_ecc_private_key_en(),
        )),
    )?;
    let signed = if variant == 2 {
        // DPE signing helper (runtime/src/dpe_crypto.rs), raw message hashed with SHA-384.
        dpe_sign_ec(drivers, &pub_key, msg)
    } else if variant == 0 {
        Crypto::ecdsa384_sign(
            &mut drivers.sha2_512_384,
            &mut drivers.ecc384,
            &mut drivers.trng,
            KEY_ID_TMP,
            &pub_key,
            msg,
        )
    } else {
        Crypto::ecdsa384_sign_and_verify(
            &mut drivers.sha2_512_384,
            &mut drivers.ecc384,
            &mut drivers.trng,
            KEY_ID_TMP,
            &pub_key,
            msg,
        )
    };
    // Always erase the temporary private key, then report the signing result.
    let erased = drivers.key_vault.erase_key(KEY_ID_TMP);
    let sig = signed?;
    erased?;

    let mut result = [0u8; 192];
    for (i, part) in [&pub_key.x, &pub_key.y, &sig.r, &sig.s]
        .into_iter()
        .enumerate()
    {
        let bytes = <[u8; 48]>::from(part);
        result
            .get_mut(i * 48..(i + 1) * 48)
            .ok_or_else(invalid)?
            .copy_from_slice(&bytes);
    }
    emit(out, &result)
}
