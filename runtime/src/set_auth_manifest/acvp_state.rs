// Licensed under the Apache-2.0 license

//! Test-only state builder for the `ACVP_TEST` image-metadata-collection signature targets.
//!
//! `process_image_metadata_col` hashes the metadata collection it is given and verifies the vendor and
//! owner signatures over that digest. This child module (which can see the private functions of its
//! parent) builds an `AuthManifestPreamble` that holds the vector's key and signature and calls the
//! function on the vector's message. The entry-count and size validation and the processing after the
//! signature checks are compiled out of an `acvp` build (see the [ACVP patch] marks in the parent).

use super::*;

/// Which arm to exercise.
#[derive(Clone, Copy)]
pub(crate) enum Which {
    Vendor,
    Owner,
}

fn words(bytes: &[u8; 48]) -> [u32; 12] {
    Array4x12::from(*bytes).0
}

impl SetAuthManifestCmd {
    /// Runs `process_image_metadata_col` over `msg` with the given key and signature for one arm and
    /// reports whether the ECC signature was accepted. The PQC leg that follows the ECC leg has no
    /// signature here, so the verdict is taken from the error: the arm's `..._ECC_SIGNATURE_INVALID`
    /// means rejected, anything else means the ECC leg passed.
    #[inline(never)]
    pub(crate) fn acvp_metadata_col_ecc_leg(
        drivers: &mut Drivers,
        which: Which,
        qx: &[u8; 48],
        qy: &[u8; 48],
        r: &[u8; 48],
        s: &[u8; 48],
        msg: &[u8],
    ) -> CaliptraResult<bool> {
        let mut preamble = AuthManifestPreamble::default();
        let key = ImageEccPubKey {
            x: words(qx),
            y: words(qy),
        };
        let sig = ImageEccSignature {
            r: words(r),
            s: words(s),
        };
        let expected_err = match which {
            Which::Vendor => {
                preamble.flags = AuthManifestFlags::VENDOR_SIGNATURE_REQUIRED.bits();
                preamble.vendor_pub_keys.ecc_pub_key = key;
                preamble.vendor_image_metdata_signatures.ecc_sig = sig;
                CaliptraError::RUNTIME_AUTH_MANIFEST_VENDOR_ECC_SIGNATURE_INVALID
            }
            Which::Owner => {
                // Without VENDOR_SIGNATURE_REQUIRED the vendor check is skipped.
                preamble.flags = 0;
                preamble.owner_pub_keys.ecc_pub_key = key;
                preamble.owner_image_metdata_signatures.ecc_sig = sig;
                CaliptraError::RUNTIME_AUTH_MANIFEST_OWNER_ECC_SIGNATURE_INVALID
            }
        };

        let result = drivers.abr.with_mldsa87(|mut m| {
            Self::process_image_metadata_col(
                msg,
                &preamble,
                &mut drivers.persistent_data.get_mut().fw.auth_manifest_image_metadata_col,
                &mut drivers.sha2_512_384,
                &mut drivers.ecc384,
                &mut drivers.sha256,
                &mut m,
                FwVerificationPqcKeyType::LMS,
                true,
                true,
            )
        });
        // After the ECC leg the PQC leg runs on a preamble without PQC data, so it fails with one of these.
        let pqc_leg_errors = [
            CaliptraError::RUNTIME_AUTH_MANIFEST_LMS_VENDOR_PUB_KEY_INVALID,
            CaliptraError::RUNTIME_AUTH_MANIFEST_VENDOR_LMS_SIGNATURE_INVALID,
            CaliptraError::RUNTIME_AUTH_MANIFEST_LMS_OWNER_PUB_KEY_INVALID,
            CaliptraError::RUNTIME_AUTH_MANIFEST_OWNER_LMS_SIGNATURE_INVALID,
        ];
        match result {
            Ok(()) => Ok(true),
            Err(e) if e == expected_err => Ok(false),
            Err(e) if pqc_leg_errors.contains(&e) => Ok(true),
            // Any other error means the ECC leg was not reached or failed for another reason.
            Err(e) => Err(e),
        }
    }
}

/// Which of the four LMS legs to exercise.
#[derive(Clone, Copy)]
pub(crate) enum LmsWhich {
    VendorSignedData,
    OwnerPubKeys,
    VendorMetadataCol,
    OwnerMetadataCol,
}

impl SetAuthManifestCmd {
    /// Runs the LMS leg of one manifest verifier with the lab's 48-byte message as the digest (the ECC leg is
    /// skipped by the `acvp` argument of the function). Reports whether the LMS signature was accepted.
    #[inline(never)]
    pub(crate) fn acvp_lms_leg(
        drivers: &mut Drivers,
        which: LmsWhich,
        pk: &[u8; 48],
        sig: &[u8; 1620],
        digest_bytes: &[u8; 48],
    ) -> CaliptraResult<bool> {
        let mut digest: ImageDigest384 = [0u32; 12];
        for (word, chunk) in digest.iter_mut().zip(digest_bytes.chunks_exact(4)) {
            *word = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        let mut preamble = AuthManifestPreamble::default();
        let mut fw = ImagePreamble::default();
        let invalid = CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS;
        let (signature_invalid, pk_dst, sig_dst) = match which {
            LmsWhich::VendorSignedData => (
                CaliptraError::RUNTIME_AUTH_MANIFEST_VENDOR_LMS_SIGNATURE_INVALID,
                &mut fw.vendor_pqc_active_pub_key.0[..],
                &mut preamble.vendor_pub_keys_signatures.pqc_sig.0[..],
            ),
            LmsWhich::OwnerPubKeys => (
                CaliptraError::RUNTIME_AUTH_MANIFEST_OWNER_LMS_SIGNATURE_INVALID,
                &mut fw.owner_pub_keys.pqc_pub_key.0[..],
                &mut preamble.owner_pub_keys_signatures.pqc_sig.0[..],
            ),
            LmsWhich::VendorMetadataCol => {
                preamble.flags = AuthManifestFlags::VENDOR_SIGNATURE_REQUIRED.bits();
                (
                    CaliptraError::RUNTIME_AUTH_MANIFEST_VENDOR_LMS_SIGNATURE_INVALID,
                    &mut preamble.vendor_pub_keys.pqc_pub_key.0[..],
                    &mut preamble.vendor_image_metdata_signatures.pqc_sig.0[..],
                )
            }
            LmsWhich::OwnerMetadataCol => (
                CaliptraError::RUNTIME_AUTH_MANIFEST_OWNER_LMS_SIGNATURE_INVALID,
                &mut preamble.owner_pub_keys.pqc_pub_key.0[..],
                &mut preamble.owner_image_metdata_signatures.pqc_sig.0[..],
            ),
        };
        pk_dst.get_mut(..pk.len()).ok_or(invalid)?.copy_from_slice(pk);
        sig_dst.get_mut(..sig.len()).ok_or(invalid)?.copy_from_slice(sig);

        let result = drivers.abr.with_mldsa87(|mut m| match which {
            LmsWhich::VendorSignedData => Self::verify_vendor_signed_data(
                &preamble,
                &fw,
                &mut drivers.sha2_512_384,
                &mut drivers.ecc384,
                &mut drivers.sha256,
                &mut m,
                FwVerificationPqcKeyType::LMS,
                Some((&digest, true)),
            ),
            LmsWhich::OwnerPubKeys => Self::verify_owner_pub_keys(
                &preamble,
                &fw,
                &mut drivers.sha2_512_384,
                &mut drivers.ecc384,
                &mut drivers.sha256,
                &mut m,
                FwVerificationPqcKeyType::LMS,
                Some((&digest, true)),
            ),
            LmsWhich::VendorMetadataCol => Self::verify_vendor_image_metadata_col(
                &preamble,
                &digest,
                &mut drivers.ecc384,
                &mut drivers.sha256,
                &mut m,
                &mut drivers.sha2_512_384,
                FwVerificationPqcKeyType::LMS,
                &[],
                true,
            ),
            LmsWhich::OwnerMetadataCol => Self::verify_owner_image_metadata_col(
                &preamble,
                &digest,
                &mut drivers.ecc384,
                &mut drivers.sha256,
                &mut m,
                &mut drivers.sha2_512_384,
                FwVerificationPqcKeyType::LMS,
                &[],
                true,
            ),
        });
        match result {
            Ok(()) => Ok(true),
            Err(e) if e == signature_invalid => Ok(false),
            Err(e) => Err(e),
        }
    }
}

/// Which manifest verifier's ECC leg to exercise on the lab's message.
#[derive(Clone, Copy)]
pub(crate) enum EccWhich {
    /// `verify_vendor_signed_data` (the `ecc384_verify` folders).
    VendorSignedData,
    /// `verify_owner_pub_keys`.
    OwnerPubKeys,
}

impl SetAuthManifestCmd {
    /// Runs the ECC leg of `which` on the lab's message: the message is hashed here with the helper the
    /// functions use (`sha384_digest`), the digest replaces the digest of the fixed preamble range, and the
    /// key and signature are placed where the function reads them. The PQC leg that follows has no signature,
    /// so the verdict is the ECC leg's: its ECC-invalid error means rejected, an LMS-leg error or success
    /// means the ECC signature was accepted, any other error is a failure.
    #[inline(never)]
    pub(crate) fn acvp_ecc_leg(
        drivers: &mut Drivers,
        which: EccWhich,
        qx: &[u8; 48],
        qy: &[u8; 48],
        r: &[u8; 48],
        s: &[u8; 48],
        msg: &[u8],
    ) -> CaliptraResult<bool> {
        let digest = Self::sha384_digest(&mut drivers.sha2_512_384, msg, 0, msg.len() as u32)?;
        let mut preamble = AuthManifestPreamble::default();
        let mut fw = ImagePreamble::default();
        let key = ImageEccPubKey {
            x: words(qx),
            y: words(qy),
        };
        let sig = ImageEccSignature {
            r: words(r),
            s: words(s),
        };
        let (expected_err, lms_errors) = match which {
            EccWhich::VendorSignedData => {
                fw.vendor_ecc_active_pub_key = key;
                preamble.vendor_pub_keys_signatures.ecc_sig = sig;
                (
                    CaliptraError::RUNTIME_AUTH_MANIFEST_VENDOR_ECC_SIGNATURE_INVALID,
                    [
                        CaliptraError::RUNTIME_AUTH_MANIFEST_LMS_VENDOR_PUB_KEY_INVALID,
                        CaliptraError::RUNTIME_AUTH_MANIFEST_VENDOR_LMS_SIGNATURE_INVALID,
                    ],
                )
            }
            EccWhich::OwnerPubKeys => {
                fw.owner_pub_keys.ecc_pub_key = key;
                preamble.owner_pub_keys_signatures.ecc_sig = sig;
                (
                    CaliptraError::RUNTIME_AUTH_MANIFEST_OWNER_ECC_SIGNATURE_INVALID,
                    [
                        CaliptraError::RUNTIME_AUTH_MANIFEST_LMS_OWNER_PUB_KEY_INVALID,
                        CaliptraError::RUNTIME_AUTH_MANIFEST_OWNER_LMS_SIGNATURE_INVALID,
                    ],
                )
            }
        };
        let result = drivers.abr.with_mldsa87(|mut m| match which {
            EccWhich::VendorSignedData => Self::verify_vendor_signed_data(
                &preamble,
                &fw,
                &mut drivers.sha2_512_384,
                &mut drivers.ecc384,
                &mut drivers.sha256,
                &mut m,
                FwVerificationPqcKeyType::LMS,
                Some((&digest, false)),
            ),
            EccWhich::OwnerPubKeys => Self::verify_owner_pub_keys(
                &preamble,
                &fw,
                &mut drivers.sha2_512_384,
                &mut drivers.ecc384,
                &mut drivers.sha256,
                &mut m,
                FwVerificationPqcKeyType::LMS,
                Some((&digest, false)),
            ),
        });
        match result {
            Ok(()) => Ok(true),
            Err(e) if e == expected_err => Ok(false),
            Err(e) if lms_errors.contains(&e) => Ok(true),
            Err(e) => Err(e),
        }
    }
}
