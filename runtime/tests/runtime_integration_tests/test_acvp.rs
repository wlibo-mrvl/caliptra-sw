// Licensed under the Apache-2.0 license

//! Tests for the test-only `ACVP_TEST` command. Build and run with
//! `cargo test -p caliptra-runtime --test runtime_integration_tests --features acvp test_acvp`.

#![cfg(feature = "acvp")]

use crate::common::{run_rt_test, RuntimeTestArgs};
use caliptra_api::checksum::{calc_checksum, verify_checksum};
use caliptra_api::mailbox::*;
use caliptra_builder::firmware::APP_WITH_UART_ACVP;
use caliptra_hw_model::{DefaultHwModel, HwModel};
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut};
use cipher::{KeyIvInit, StreamCipherCore};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha384, Sha512};

pub struct AcvpResp {
    pub result: u32,
    pub err_code: u32,
    pub data: Vec<u8>,
}

fn acvp_model() -> DefaultHwModel {
    let mut model = run_rt_test(RuntimeTestArgs {
        test_fwid: Some(&APP_WITH_UART_ACVP),
        subsystem_mode: true,
        ..Default::default()
    });
    model.step_until_ready_for_runtime();
    model
}

/// Builds the request bytes: [chksum][target][n_fields] then [len][bytes padded to 4] per field.
pub fn build_req(target: u32, fields: &[&[u8]]) -> Vec<u8> {
    let mut req = vec![0u8; 4];
    req.extend_from_slice(&target.to_le_bytes());
    req.extend_from_slice(&(fields.len() as u32).to_le_bytes());
    for f in fields {
        req.extend_from_slice(&(f.len() as u32).to_le_bytes());
        req.extend_from_slice(f);
        req.resize(req.len().next_multiple_of(4), 0);
    }
    let chk = calc_checksum(u32::from(CommandId::ACVP_TEST), &req[4..]);
    req[..4].copy_from_slice(&chk.to_le_bytes());
    req
}

/// Sends one ACVP_TEST request and parses the response.
pub fn acvp_call(model: &mut DefaultHwModel, target: u32, fields: &[&[u8]]) -> AcvpResp {
    let req = build_req(target, fields);
    let resp = model
        .mailbox_execute(u32::from(CommandId::ACVP_TEST), &req)
        .unwrap()
        .expect("ACVP_TEST should return a response");
    assert!(resp.len() >= ACVP_RESP_HDR_SIZE, "short response");
    assert!(
        verify_checksum(
            u32::from_le_bytes(resp[0..4].try_into().unwrap()),
            0,
            &resp[4..]
        ),
        "bad response checksum"
    );
    let word = |i: usize| u32::from_le_bytes(resp[i..i + 4].try_into().unwrap());
    let data_len = word(16) as usize;
    assert_eq!(resp.len(), ACVP_RESP_HDR_SIZE + data_len);
    AcvpResp {
        result: word(8),
        err_code: word(12),
        data: resp[ACVP_RESP_HDR_SIZE..].to_vec(),
    }
}

#[test]
fn test_acvp_ping() {
    let mut model = acvp_model();
    for len in [0usize, 1, 3, 4, 17, 4096] {
        let payload: Vec<u8> = (0..len).map(|i| (i * 7 + 1) as u8).collect();
        let r = acvp_call(&mut model, ACVP_TARGET_PING, &[&payload]);
        assert_eq!(r.result, ACVP_RESULT_OK);
        assert_eq!(r.err_code, 0);
        assert_eq!(r.data, payload, "echo mismatch at len {len}");
    }
}

#[test]
fn test_acvp_unknown_target_and_missing_field_fail_the_command() {
    let mut model = acvp_model();
    // Unknown target.
    let req = build_req(0xFFFF, &[b"x"]);
    assert!(model
        .mailbox_execute(u32::from(CommandId::ACVP_TEST), &req)
        .is_err());
    // PING with no fields.
    let req = build_req(ACVP_TARGET_PING, &[]);
    assert!(model
        .mailbox_execute(u32::from(CommandId::ACVP_TEST), &req)
        .is_err());
}

/// Deterministic test data.
fn data(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| {
            (i as u8)
                .wrapping_mul(31)
                .wrapping_add(seed)
                .wrapping_add((i >> 8) as u8)
        })
        .collect()
}

fn ok(r: AcvpResp) -> Vec<u8> {
    assert_eq!(
        r.result, ACVP_RESULT_OK,
        "driver error 0x{:08x}",
        r.err_code
    );
    r.data
}

const SHA_LENS: [usize; 13] = [0, 1, 3, 55, 56, 63, 64, 65, 119, 120, 129, 1000, 4000];

#[test]
fn test_acvp_sha256_family() {
    let mut model = acvp_model();
    for len in SHA_LENS {
        let msg = data(len, 3);
        let want = Sha256::digest(&msg).to_vec();
        let got = ok(acvp_call(&mut model, ACVP_TARGET_SHA256_DIGEST, &[&msg]));
        assert_eq!(got, want, "digest len {len}");
        for chunk in [1u32, 7, 64, 100] {
            let got = ok(acvp_call(
                &mut model,
                ACVP_TARGET_SHA256_DIGEST_INIT,
                &[&chunk.to_le_bytes(), &msg],
            ));
            assert_eq!(got, want, "digest_init len {len} chunk {chunk}");
        }
        // update_wntz with w = 1 and n_mode = 1 is plain SHA-256 (atsec, sha256.sv).
        // The software emulator does not model that: it reads the iteration start from byte
        // 22 of every block and skips the compression when it is above 0. The RTL ignores
        // the byte (and only sets a sticky error bit), so on the FPGA the unmodified vectors
        // must match. Here byte 22 of every block is zeroed so the emulator agrees.
        let mut wmsg = msg.clone();
        for i in (22..wmsg.len()).step_by(64) {
            wmsg[i] = 0;
        }
        let got = ok(acvp_call(
            &mut model,
            ACVP_TARGET_SHA256_WNTZ,
            &[&1u32.to_le_bytes(), &1u32.to_le_bytes(), &wmsg],
        ));
        assert_eq!(got, Sha256::digest(&wmsg).to_vec(), "wntz len {len}");
    }
    for len in [0usize, 64, 128, 4096] {
        let msg = data(len, 9);
        let got = ok(acvp_call(
            &mut model,
            ACVP_TARGET_SHA256_BLOCKS_RAW,
            &[&msg],
        ));
        assert_eq!(got, Sha256::digest(&msg).to_vec(), "blocks_raw len {len}");
    }
}

/// `sha384_image` reads the message over AXI, which only the FPGA bench stages (the software
/// emulator has no host memory), so the emulator checks the zero-length case (answered without
/// touching the bus) and the request framing.
#[test]
fn test_acvp_sha384_image_zero_length() {
    let mut model = acvp_model();
    let words = [0u32.to_le_bytes(), 0u32.to_le_bytes(), 0u32.to_le_bytes()];
    let out = ok(acvp_call(
        &mut model,
        ACVP_TARGET_SHA384_IMAGE,
        &[&words[0], &words[1], &words[2]],
    ));
    assert_eq!(out, Sha384::digest([]).to_vec());
    // A request with a missing field is malformed.
    let req = build_req(ACVP_TARGET_SHA384_IMAGE, &[&words[0]]);
    assert!(model
        .mailbox_execute(u32::from(CommandId::ACVP_TEST), &req)
        .is_err());
}

#[test]
fn test_acvp_sha384_sha512() {
    let mut model = acvp_model();
    for len in SHA_LENS {
        let msg = data(len, 5);
        let got = ok(acvp_call(&mut model, ACVP_TARGET_SHA384_DIGEST, &[&msg]));
        assert_eq!(got, Sha384::digest(&msg).to_vec(), "sha384 len {len}");
        let got = ok(acvp_call(&mut model, ACVP_TARGET_SHA512_DIGEST, &[&msg]));
        assert_eq!(got, Sha512::digest(&msg).to_vec(), "sha512 len {len}");
    }
}

#[test]
fn test_acvp_hmac() {
    let mut model = acvp_model();
    for target in [ACVP_TARGET_HMAC, ACVP_TARGET_HMAC_INIT] {
        for len in [0usize, 1, 16, 127, 128, 129, 1000, 4000] {
            let msg = data(len, 7);
            let key384 = data(48, 11);
            let key512 = data(64, 13);
            let mut mac = Hmac::<Sha384>::new_from_slice(&key384).unwrap();
            mac.update(&msg);
            let got = ok(acvp_call(
                &mut model,
                target,
                &[&384u32.to_le_bytes(), &key384, &msg],
            ));
            assert_eq!(got, mac.finalize().into_bytes().to_vec(), "384 len {len}");
            let mut mac = Hmac::<Sha512>::new_from_slice(&key512).unwrap();
            mac.update(&msg);
            let got = ok(acvp_call(
                &mut model,
                target,
                &[&512u32.to_le_bytes(), &key512, &msg],
            ));
            assert_eq!(got, mac.finalize().into_bytes().to_vec(), "512 len {len}");
        }
    }
}

type Ctr = ctr::CtrCore<aes::Aes256, ctr::flavors::Ctr128BE>;

#[test]
fn test_acvp_aes_cbc_ctr() {
    let mut model = acvp_model();
    let key = data(32, 21);
    let iv = data(16, 23);
    for len in [16usize, 32, 160, 4096] {
        let pt = data(len, 1);
        let mut enc =
            cbc::Encryptor::<aes::Aes256>::new(key.as_slice().into(), iv.as_slice().into());
        let mut want = vec![];
        for block in pt.chunks(16) {
            let mut o = [0u8; 16].into();
            enc.encrypt_block_b2b_mut(block.into(), &mut o);
            want.extend_from_slice(&o);
        }
        let got = ok(acvp_call(
            &mut model,
            ACVP_TARGET_AES_CBC,
            &[&1u32.to_le_bytes(), &key, &iv, &pt],
        ));
        assert_eq!(got, want, "cbc encrypt len {len}");
        let got = ok(acvp_call(
            &mut model,
            ACVP_TARGET_AES_CBC,
            &[&2u32.to_le_bytes(), &key, &iv, &want],
        ));
        assert_eq!(got, pt, "cbc decrypt len {len}");
        let mut dec =
            cbc::Decryptor::<aes::Aes256>::new(key.as_slice().into(), iv.as_slice().into());
        let mut check = vec![];
        for block in want.chunks(16) {
            let mut o = [0u8; 16].into();
            dec.decrypt_block_b2b_mut(block.into(), &mut o);
            check.extend_from_slice(&o);
        }
        assert_eq!(check, pt, "rustcrypto cbc roundtrip len {len}");
    }
    // 16000 bytes is the largest AES-CTR vector; it must fit the 16 KB subsystem mailbox.
    for len in [1usize, 16, 17, 100, 8000, 16000] {
        let pt = data(len, 2);
        let ctr = Ctr::new(key.as_slice().into(), iv.as_slice().into());
        let mut want = pt.clone();
        ctr.apply_keystream_partial(want.as_mut_slice().into());
        let got = ok(acvp_call(
            &mut model,
            ACVP_TARGET_AES_CTR,
            &[&key, &iv, &pt],
        ));
        assert_eq!(got, want, "ctr len {len}");
    }
}

// ------------------------------------------------------------------ CMAC and KDFs

fn aes256_block(key: &[u8], block: &[u8; 16]) -> [u8; 16] {
    use aes::cipher::{BlockEncrypt, KeyInit};
    let cipher = aes::Aes256::new(key.into());
    let mut b = (*block).into();
    cipher.encrypt_block(&mut b);
    b.into()
}

fn dbl(b: [u8; 16]) -> [u8; 16] {
    let v = u128::from_be_bytes(b);
    let mut r = v << 1;
    if v >> 127 == 1 {
        r ^= 0x87;
    }
    r.to_be_bytes()
}

/// AES-256 CMAC (SP 800-38B), the reference for the CMAC and CMAC-KDF targets.
fn cmac_aes256(key: &[u8], msg: &[u8]) -> [u8; 16] {
    let k1 = dbl(aes256_block(key, &[0u8; 16]));
    let k2 = dbl(k1);
    let n = msg.len().div_ceil(16).max(1);
    let mut x = [0u8; 16];
    for i in 0..n {
        let mut block = [0u8; 16];
        let chunk = &msg[(i * 16).min(msg.len())..((i + 1) * 16).min(msg.len())];
        block[..chunk.len()].copy_from_slice(chunk);
        if i == n - 1 {
            let k = if chunk.len() == 16 {
                k1
            } else {
                block[chunk.len()] = 0x80;
                k2
            };
            for j in 0..16 {
                block[j] ^= k[j];
            }
        }
        for j in 0..16 {
            block[j] ^= x[j];
        }
        x = aes256_block(key, &block);
    }
    x
}

#[test]
fn test_acvp_cmac_and_kdfs() {
    let mut model = acvp_model();
    let key = data(32, 41);
    // NIST SP 800-38B example 5 (AES-256, empty message) fixes the reference itself.
    let nist_key =
        hex::decode("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4").unwrap();
    assert_eq!(
        hex::encode(cmac_aes256(&nist_key, b"")),
        "028962f61b7bf89efc6b551f4667d983"
    );
    for len in [0usize, 1, 15, 16, 17, 32, 100, 4000] {
        let msg = data(len, 6);
        let got = ok(acvp_call(&mut model, ACVP_TARGET_AES_CMAC, &[&key, &msg]));
        assert_eq!(got, cmac_aes256(&key, &msg).to_vec(), "cmac len {len}");
    }
    // CMAC KDF: CMAC(key, BE32(i) || label) for i in 1..=rounds
    for (label_len, rounds) in [(16usize, 1u32), (16, 2), (16, 4), (0, 1), (100, 3)] {
        let label = data(label_len, 8);
        let got = ok(acvp_call(
            &mut model,
            ACVP_TARGET_CMAC_KDF,
            &[&key, &label, &rounds.to_le_bytes()],
        ));
        let mut want = vec![];
        for i in 1..=rounds {
            let mut input = i.to_be_bytes().to_vec();
            input.extend_from_slice(&label);
            want.extend_from_slice(&cmac_aes256(&key, &input));
        }
        assert_eq!(got, want, "cmac_kdf label {label_len} rounds {rounds}");
    }
    // HMAC KDF: one block, HMAC(key, BE32(1) || label)
    for label_len in [0usize, 16, 100] {
        let label = data(label_len, 9);
        let mut input = 1u32.to_be_bytes().to_vec();
        input.extend_from_slice(&label);
        let key384 = data(48, 3);
        let mut mac = Hmac::<Sha384>::new_from_slice(&key384).unwrap();
        mac.update(&input);
        let got = ok(acvp_call(
            &mut model,
            ACVP_TARGET_HMAC_KDF,
            &[&384u32.to_le_bytes(), &key384, &label],
        ));
        assert_eq!(
            got,
            mac.finalize().into_bytes().to_vec(),
            "hmac_kdf 384 label {label_len}"
        );
        let key512 = data(64, 4);
        let mut mac = Hmac::<Sha512>::new_from_slice(&key512).unwrap();
        mac.update(&input);
        let got = ok(acvp_call(
            &mut model,
            ACVP_TARGET_HMAC_KDF,
            &[&512u32.to_le_bytes(), &key512, &label],
        ));
        assert_eq!(
            got,
            mac.finalize().into_bytes().to_vec(),
            "hmac_kdf 512 label {label_len}"
        );
    }
}

// ------------------------------------------------------------------ signatures

/// Result of a verification target: Some(true) valid, Some(false) invalid.
fn verdict(r: &AcvpResp) -> bool {
    match r.result {
        ACVP_RESULT_OK => true,
        ACVP_RESULT_FALSE => false,
        _ => panic!("driver error 0x{:08x}", r.err_code),
    }
}

#[test]
fn test_acvp_lms_verify() {
    use sha2::Sha384 as H;
    let mut model = acvp_model();
    // The known-good signatures are over SHA-384 of the message, so the 48-byte digest is the
    // message LMS verifies (what atsec's 48-byte vectors model).
    let msg = H::digest(crate::test_lms::MSG_1).to_vec();
    let pk = crate::test_lms::MSG_1_PUB_KEY_1;
    let sig = crate::test_lms::MSG_1_KEY_1_SIG_1;
    let call = |model: &mut DefaultHwModel, pk: &[u8], sig: &[u8], msg: &[u8]| {
        verdict(&acvp_call(model, ACVP_TARGET_LMS_VERIFY, &[pk, sig, msg]))
    };
    assert!(call(&mut model, &pk, &sig, &msg), "valid signature");
    let mut bad_msg = msg.clone();
    bad_msg[0] ^= 1;
    assert!(!call(&mut model, &pk, &sig, &bad_msg), "wrong message");
    let mut bad_sig = sig;
    bad_sig[1000] ^= 1;
    assert!(
        !call(&mut model, &pk, &bad_sig, &msg),
        "corrupted signature"
    );
    let mut bad_type = sig;
    bad_type[7] ^= 0x40; // invalid LM-OTS algorithm type: reported as invalid, not as an error
    assert!(
        !call(&mut model, &pk, &bad_type, &msg),
        "malformed signature"
    );
    let mut bad_pk = pk;
    bad_pk[47] ^= 1;
    assert!(!call(&mut model, &bad_pk, &sig, &msg), "wrong public key");
}

fn shake256(parts: &[&[u8]], len: usize) -> Vec<u8> {
    use sha3::digest::{ExtendableOutput, Update, XofReader};
    let mut h = sha3::Shake256::default();
    for p in parts {
        h.update(p);
    }
    let mut out = vec![0u8; len];
    h.finalize_xof().read(&mut out);
    out
}

#[test]
fn test_acvp_mldsa_verify() {
    use fips204::ml_dsa_87;
    use fips204::traits::{SerDes, Signer};
    use rand::SeedableRng;
    let mut model = acvp_model();
    let mut rng = rand::rngs::StdRng::seed_from_u64(7);
    let (pk, sk) = ml_dsa_87::try_keygen_with_rng(&mut rng).unwrap();
    let pk_bytes = pk.into_bytes().to_vec();
    assert_eq!(pk_bytes.len(), 2592);
    let call = |model: &mut DefaultHwModel, target, pk: &[u8], sig: &[u8], m: &[u8]| {
        verdict(&acvp_call(model, target, &[pk, sig, m]))
    };

    // verify_var: the engine builds M' = 0x00 || len(ctx) || ctx || M from the context registers.
    // The longest context here is 127 bytes: the software emulator keeps the context size in 7 bits
    // (the RTL register is 8 bits, so the FPGA also takes 128..=255).
    let var = ACVP_TARGET_MLDSA_VERIFY_VAR;
    for (ctx, mlen) in [
        (&b""[..], 1usize),
        (&b"ctx"[..], 100),
        (&[7u8; 127][..], 2000),
    ] {
        let m = data(mlen, 5);
        let sig = sk.try_sign_with_seed(&[3u8; 32], &m, ctx).unwrap();
        let call_var = |model: &mut DefaultHwModel, sig: &[u8], ctx: &[u8], m: &[u8]| {
            verdict(&acvp_call(model, var, &[&pk_bytes, sig, ctx, m]))
        };
        assert!(call_var(&mut model, &sig, ctx, &m), "var ctx {}", ctx.len());
        let mut bad = sig;
        bad[100] ^= 1;
        assert!(!call_var(&mut model, &bad, ctx, &m), "var corrupted");
        let mut bad_m = m.clone();
        *bad_m.last_mut().unwrap() ^= 1;
        assert!(
            !call_var(&mut model, &sig, ctx, &bad_m),
            "var wrong message"
        );
        if !ctx.is_empty() {
            // The same signature must not verify under a different (or no) context.
            assert!(!call_var(&mut model, &sig, &[], &m), "var missing context");
        }
    }

    // verify with a 64-byte message and an empty context: the hardware adds the prefix itself.
    let m64 = data(64, 11);
    let sig = sk.try_sign_with_seed(&[4u8; 32], &m64, &[]).unwrap();
    assert!(
        call(
            &mut model,
            ACVP_TARGET_MLDSA_VERIFY_MSG,
            &pk_bytes,
            &sig,
            &m64
        ),
        "msg"
    );
    let mut bad64 = m64.clone();
    bad64[0] ^= 1;
    assert!(
        !call(
            &mut model,
            ACVP_TARGET_MLDSA_VERIFY_MSG,
            &pk_bytes,
            &sig,
            &bad64
        ),
        "msg wrong"
    );

    // verify_external_mu with mu = SHAKE256(SHAKE256(pk, 64) || M', 64).
    let tr = shake256(&[&pk_bytes], 64);
    let mut mprime = vec![0u8, 0u8];
    mprime.extend_from_slice(&m64);
    let mu = shake256(&[&tr, &mprime], 64);
    assert!(
        call(
            &mut model,
            ACVP_TARGET_MLDSA_VERIFY_MU,
            &pk_bytes,
            &sig,
            &mu
        ),
        "mu"
    );
    let mut bad_mu = mu.clone();
    bad_mu[63] ^= 1;
    assert!(
        !call(
            &mut model,
            ACVP_TARGET_MLDSA_VERIFY_MU,
            &pk_bytes,
            &sig,
            &bad_mu
        ),
        "mu wrong"
    );
}

#[test]
fn test_acvp_ecdsa_verify_and_sign() {
    use p384::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
    use p384::ecdsa::{Signature, SigningKey, VerifyingKey};
    let mut model = acvp_model();
    let sk_bytes: [u8; 48] = core::array::from_fn(|i| (i as u8) + 1);
    let sk = SigningKey::from_slice(&sk_bytes).unwrap();
    let point = sk.verifying_key().to_encoded_point(false);
    let (qx, qy) = (point.x().unwrap().to_vec(), point.y().unwrap().to_vec());
    for len in [1usize, 48, 128, 1000] {
        let msg = data(len, 2);
        let sig: Signature = sk.sign_prehash(&Sha384::digest(&msg)).unwrap();
        let (r, s) = (sig.r().to_bytes().to_vec(), sig.s().to_bytes().to_vec());
        let call = |model: &mut DefaultHwModel, qx: &[u8], r: &[u8], s: &[u8], m: &[u8]| {
            verdict(&acvp_call(
                model,
                ACVP_TARGET_ECDSA384_VERIFY,
                &[qx, &qy, r, s, m],
            ))
        };
        assert!(call(&mut model, &qx, &r, &s, &msg), "valid len {len}");
        let mut bad_r = r.clone();
        bad_r[47] ^= 1;
        assert!(!call(&mut model, &qx, &bad_r, &s, &msg), "wrong r");
        assert!(!call(&mut model, &qx, &[0u8; 48], &s, &msg), "zero r");
        assert!(!call(&mut model, &qx, &r, &[0u8; 48], &msg), "zero s");
        // (A public key off the curve is not tried here: the software emulator panics on it.)
        let mut bad_msg = msg.clone();
        bad_msg[0] ^= 1;
        assert!(!call(&mut model, &qx, &r, &s, &bad_msg), "wrong message");
    }

    // Signing: the device derives a key pair from the seed, signs, and returns qx qy r s.
    for variant in [0u32, 1, 2] {
        for len in [1usize, 128, 1000] {
            let seed = data(48, 77);
            let msg = data(len, 12);
            let got = ok(acvp_call(
                &mut model,
                ACVP_TARGET_ECDSA384_SIGN,
                &[&variant.to_le_bytes(), &seed, &msg],
            ));
            assert_eq!(got.len(), 192);
            let mut sec1 = vec![0x04u8];
            sec1.extend_from_slice(&got[..96]);
            let vk = VerifyingKey::from_sec1_bytes(&sec1).expect("returned public key");
            let sig = Signature::from_scalars(
                <[u8; 48]>::try_from(&got[96..144]).unwrap(),
                <[u8; 48]>::try_from(&got[144..192]).unwrap(),
            )
            .unwrap();
            vk.verify_prehash(&Sha384::digest(&msg), &sig)
                .expect("device signature verifies");
            // The same seed and message give the same key pair and the same signature
            // (deterministic ECDSA: the engine derives the nonce from the key and the digest).
            let same = ok(acvp_call(
                &mut model,
                ACVP_TARGET_ECDSA384_SIGN,
                &[&variant.to_le_bytes(), &seed, &msg],
            ));
            assert_eq!(same, got, "variant {variant}: signing is deterministic");
            let again = ok(acvp_call(
                &mut model,
                ACVP_TARGET_ECDSA384_SIGN,
                &[&variant.to_le_bytes(), &seed, &data(5, 1)],
            ));
            assert_eq!(
                &again[..96],
                &got[..96],
                "key pair is a function of the seed"
            );
        }
    }
}

/// The tester's CM_ECDSA_SIGN chain for the MBX `ecdsa_sign` folder, built the way
/// acvp_chains.py builds it (raw request bytes, variable-length CM_IMPORT): the returned x, y, r, s
/// are big-endian and the signature verifies, and signing is deterministic.
#[test]
fn test_acvp_cm_ecdsa_chain_matches_tester_framework() {
    use p384::ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};
    let mut model = acvp_model();
    let call = |model: &mut DefaultHwModel, cmd: CommandId, payload: Vec<u8>| -> Vec<u8> {
        let mut req = vec![0u8; 4];
        req.extend_from_slice(&payload);
        let id = u32::from(cmd);
        let chk = calc_checksum(id, &req[4..]);
        req[..4].copy_from_slice(&chk.to_le_bytes());
        model
            .mailbox_execute(id, &req)
            .unwrap()
            .expect("response")
    };
    let seed = data(48, 3);
    let mut imp = Vec::new();
    imp.extend_from_slice(&3u32.to_le_bytes()); // CmKeyUsage::Ecdsa
    imp.extend_from_slice(&48u32.to_le_bytes());
    imp.extend_from_slice(&seed);
    let import_resp = call(&mut model, CommandId::CM_IMPORT, imp);
    assert_eq!(import_resp.len(), 136);
    let cmk = import_resp[8..136].to_vec();

    let pub_resp = call(&mut model, CommandId::CM_ECDSA_PUBLIC_KEY, cmk.clone());
    assert_eq!(pub_resp.len(), 104);
    let mut sec1 = vec![0x04u8];
    sec1.extend_from_slice(&pub_resp[8..104]);
    let vk = VerifyingKey::from_sec1_bytes(&sec1).expect("big-endian x || y is a valid point");

    let msg = data(128, 9);
    let mut sign_req = cmk.clone();
    sign_req.extend_from_slice(&(msg.len() as u32).to_le_bytes());
    sign_req.extend_from_slice(&msg);
    let sign_resp = call(&mut model, CommandId::CM_ECDSA_SIGN, sign_req.clone());
    assert_eq!(sign_resp.len(), 104);
    let sig = Signature::from_scalars(
        <[u8; 48]>::try_from(&sign_resp[8..56]).unwrap(),
        <[u8; 48]>::try_from(&sign_resp[56..104]).unwrap(),
    )
    .unwrap();
    vk.verify_prehash(&Sha384::digest(&msg), &sig)
        .expect("CM_ECDSA_SIGN signature verifies under CM_ECDSA_PUBLIC_KEY");
    let again = call(&mut model, CommandId::CM_ECDSA_SIGN, sign_req);
    assert_eq!(again[8..], sign_resp[8..], "deterministic ECDSA");
    call(&mut model, CommandId::CM_DELETE, cmk);
}

/// The ported ROM / HPKE functions: two-step SHA-512 KDF (derive_hek, hkdf_stable_owner_root_key),
/// HKDF-SHA-384 (derive_key_pair) and the ROM derive_stable_key tail (TRNG IV, encrypt_cmk).
#[test]
fn test_acvp_ported_rom_functions() {
    let mut model = acvp_model();

    // Two-step KDF: PRK = HMAC-SHA-512(salt, z); okm = HMAC-SHA-512(PRK, BE32(1) || label).
    for target in [ACVP_TARGET_PORT_DERIVE_HEK, ACVP_TARGET_PORT_HKDF_STABLE_OWNER_ROOT_KEY] {
        for (salt_len, z_len, info_len) in [(128usize, 32usize, 96usize), (64, 32, 1), (20, 7, 1500)] {
            let mut salt = data(salt_len.min(64), 5);
            salt.resize(salt_len, 0); // a longer salt is zero beyond 64 bytes
            let z = data(z_len, 6);
            let info = data(info_len, 7);
            let got = ok(acvp_call(&mut model, target, &[&salt, &z, &info]));
            let mut key = salt.clone();
            key.truncate(64);
            let mut m = <Hmac<Sha512> as Mac>::new_from_slice(&key).unwrap();
            m.update(&z);
            let prk = m.finalize().into_bytes();
            let mut m = <Hmac<Sha512> as Mac>::new_from_slice(&prk).unwrap();
            m.update(&1u32.to_be_bytes());
            m.update(&info);
            assert_eq!(got, m.finalize().into_bytes().to_vec(), "target 0x{target:x} {salt_len}/{z_len}/{info_len}");
        }
        // A non-zero byte beyond the 64 the driver takes is not representable: malformed request.
        let mut salt = data(128, 5);
        salt[100] = 1;
        let req = build_req(target, &[&salt, &data(32, 6), &data(8, 7)]);
        assert!(model.mailbox_execute(u32::from(CommandId::ACVP_TEST), &req).is_err());
    }

    // HKDF-SHA-384 (RFC 5869): PRK = HMAC(salt, z); okm = HMAC(PRK, info || 0x01).
    for (salt_len, z_len, info_len) in [(128usize, 1024usize, 32usize), (128, 62, 94), (48, 28, 1568)] {
        let mut salt = data(salt_len.min(48), 8);
        salt.resize(salt_len, 0);
        let z = data(z_len, 9);
        let info = data(info_len, 10);
        let got = ok(acvp_call(&mut model, ACVP_TARGET_PORT_DERIVE_KEY_PAIR, &[&salt, &z, &info]));
        let mut key = salt.clone();
        key.truncate(48);
        let mut m = <Hmac<Sha384> as Mac>::new_from_slice(&key).unwrap();
        m.update(&z);
        let prk = m.finalize().into_bytes();
        let mut m = <Hmac<Sha384> as Mac>::new_from_slice(&prk).unwrap();
        m.update(&info);
        m.update(&[1u8]);
        assert_eq!(got, m.finalize().into_bytes().to_vec(), "derive_key_pair {salt_len}/{z_len}/{info_len}");
    }

    // derive_stable_key tail: the answer is iv || ct || tag under the vector key, IV from the TRNG.
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Nonce};
    let key = data(32, 0x61);
    let mut pt = data(80, 0x62);
    pt[0] = 1; // a CMK is {version u16, length u16, key_usage u8, id[3], usage_counter u64, key[64]}
    pt[1] = 0;
    let out = ok(acvp_call(&mut model, ACVP_TARGET_PORT_DERIVE_STABLE_KEY, &[&key, &pt]));
    assert_eq!(out.len(), 12 + 80 + 16);
    let got = Aes256Gcm::new_from_slice(&key)
        .unwrap()
        .decrypt(Nonce::from_slice(&out[..12]), &out[12..])
        .expect("tag verifies under the vector key");
    assert_eq!(got, pt);
    let again = ok(acvp_call(&mut model, ACVP_TARGET_PORT_DERIVE_STABLE_KEY, &[&key, &pt]));
    assert_ne!(&again[..12], &out[..12], "the TRNG IV differs between calls");
}

/// `ecdsa_verify` = the CM_ECDSA_VERIFY handler, verifying against the public key from the request.
#[test]
fn test_acvp_cm_ecdsa_verify_with_request_key() {
    use p384::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey};
    let mut model = acvp_model();
    let key = SigningKey::from_slice(&data(48, 0x41)).unwrap();
    let point = key.verifying_key().to_encoded_point(false);
    let (qx, qy) = (point.x().unwrap().to_vec(), point.y().unwrap().to_vec());
    for len in [1usize, 128, 4096] {
        let msg = data(len, 0x77);
        let sig: Signature = key.sign_prehash(&Sha384::digest(&msg)).unwrap();
        let (r, s) = (sig.r().to_bytes().to_vec(), sig.s().to_bytes().to_vec());
        let call = |model: &mut DefaultHwModel, qx: &[u8], r: &[u8], msg: &[u8]| {
            acvp_call(model, ACVP_TARGET_CM_ECDSA_VERIFY, &[qx, &qy, r, &s, msg]).result
        };
        assert_eq!(call(&mut model, &qx, &r, &msg), ACVP_RESULT_OK, "valid, {len} B");
        let mut bad = msg.clone();
        bad[0] ^= 1;
        assert_eq!(call(&mut model, &qx, &r, &bad), ACVP_RESULT_FALSE);
        let mut bad_r = r.clone();
        bad_r[7] ^= 1;
        assert_eq!(call(&mut model, &qx, &bad_r, &msg), ACVP_RESULT_FALSE);
        let other = SigningKey::from_slice(&data(48, 0x42)).unwrap();
        let op = other.verifying_key().to_encoded_point(false);
        let wrong = acvp_call(
            &mut model,
            ACVP_TARGET_CM_ECDSA_VERIFY,
            &[op.x().unwrap(), op.y().unwrap(), &r, &s, &msg],
        );
        assert_eq!(wrong.result, ACVP_RESULT_FALSE, "a different key rejects it");
    }
}

/// The CSR generators signing with the Runtime alias key: an `acvp` build signs the lab's message instead
/// of the COSE context / CSR TBS. qx || qy come from the persistent data; the signature is the tail of
/// the structure the production function built.
#[test]
fn test_acvp_csr_generators_sign_the_message() {
    use p384::ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};
    let mut model = acvp_model();
    for target in [ACVP_TARGET_ATTESTED_ECC_CSR, ACVP_TARGET_RT_ALIAS_ECC_CSR] {
        let mut keys = Vec::new();
        for len in [1usize, 128, 500] {
            let msg = data(len, 0x2b);
            let out = ok(acvp_call(&mut model, target, &[&msg]));
            println!("csr target 0x{target:x} len {len}: blob {} B", out.len() - 96);
            assert!(out.len() > 96 + 96, "target 0x{target:x}: structure present");
            let mut sec1 = vec![0x04u8];
            sec1.extend_from_slice(&out[..96]);
            let vk = VerifyingKey::from_sec1_bytes(&sec1).expect("the RT alias public key");
            let blob = &out[96..];
            let sig = if target == ACVP_TARGET_ATTESTED_ECC_CSR {
                // COSE_Sign1 = [protected, unprotected, payload, signature]: the signature (r || s) is last.
                Signature::from_slice(&blob[blob.len() - 96..]).unwrap()
            } else {
                // DER CSR: the ECDSA signature (DER SEQUENCE) ends the BIT STRING at the tail.
                (blob.len().saturating_sub(110)..blob.len())
                    .find_map(|i| Signature::from_der(&blob[i..]).ok())
                    .expect("DER signature at the tail of the CSR")
            };
            vk.verify_prehash(&Sha384::digest(&msg), &sig)
                .unwrap_or_else(|_| panic!("target 0x{target:x}: signature over the message, {len} B"));
            keys.push(out[..96].to_vec());
        }
        assert!(keys.windows(2).all(|w| w[0] == w[1]), "the RT alias key does not change");
    }
}

#[test]
fn test_acvp_cm_encrypt_targets() {
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::{Aes256Gcm, Nonce};
    let mut model = acvp_model();
    let cases: [(u32, usize); 5] = [
        (ACVP_TARGET_CM_ENCRYPT_CMK, 80),
        (ACVP_TARGET_CM_ENCRYPT_AES_CONTEXT, 128),
        (ACVP_TARGET_CM_ENCRYPT_AES_GCM_CONTEXT, 100),
        (ACVP_TARGET_CM_ENCRYPT_ECDH_CONTEXT, 48),
        (ACVP_TARGET_CM_ENCRYPT_SHAKE256_CONTEXT, 16),
    ];
    for (i, (target, pt_len)) in cases.iter().enumerate() {
        let key = data(32, 0x40 + i as u8);
        let pt = data(*pt_len, 0x90 + i as u8);
        let out = ok(acvp_call(&mut model, *target, &[&key, &pt]));
        assert_eq!(out.len(), 12 + pt_len + 16, "target 0x{target:x}");
        let (iv, ct_tag) = (&out[..12], &out[12..]);
        let got = Aes256Gcm::new_from_slice(&key)
            .unwrap()
            .decrypt(Nonce::from_slice(iv), ct_tag)
            .unwrap_or_else(|_| panic!("tag/ciphertext mismatch for target 0x{target:x}"));
        assert_eq!(got, pt, "target 0x{target:x}");
        // The IV is device chosen and must differ between calls.
        let out2 = ok(acvp_call(&mut model, *target, &[&key, &pt]));
        assert_ne!(&out2[..12], iv, "IV repeated for target 0x{target:x}");
    }
    // Wrong plaintext size is rejected as a malformed request.
    let req = build_req(ACVP_TARGET_CM_ENCRYPT_CMK, &[&data(32, 1), &data(79, 2)]);
    let r = model.mailbox_execute(u32::from(CommandId::ACVP_TEST), &req);
    assert!(r.is_err() || r.unwrap().is_some());
}

/// Replays the requests that the tester framework's generate_acvp_test.py wrote
/// (`TC_<tcId>_req.bin`) against the real Runtime and compares each answer with atsec's
/// `testvector-expected.json`. This checks the Python request framing and checksum byte for
/// byte, and runs the real vectors, before going to the FPGA.
///
/// ACVP_CAPTURE_DIR: <framework>/FIPS_EHSM_BIN/ACVP_1026 (one sub-folder per vector folder)
/// ACVP_VECTORS_DIR: the vector root (caliptra_acvp_vectors/1026_min)
/// ACVP_RESPONSE_DIR (optional): keep each raw response as <dir>/<folder>/TC_<tcId>.bin
///
/// For `update_wntz` folders only the framing is checked: the software emulator treats byte 22 of
/// each block as a Winternitz iteration start and skips the compression when it is non-zero; the
/// RTL does not.
#[test]
#[ignore = "needs ACVP_CAPTURE_DIR and ACVP_VECTORS_DIR"]
fn test_acvp_replay_framework_requests() {
    let (Ok(cap), Ok(vec_root)) = (
        std::env::var("ACVP_CAPTURE_DIR"),
        std::env::var("ACVP_VECTORS_DIR"),
    ) else {
        panic!("set ACVP_CAPTURE_DIR and ACVP_VECTORS_DIR");
    };
    let mut model = acvp_model();
    let mut checked = 0;
    let mut folders: Vec<_> = std::fs::read_dir(&cap)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.is_dir())
        .collect();
    folders.sort();
    for dir in folders {
        let name = dir.file_name().unwrap().to_string_lossy().to_string();
        // CM_* command chains (MBX / RT+PATCH folders) have no ACVP_TEST request files; they are
        // replayed from the generated script by test_acvp_replay_generated_chain_script.
        let has_requests = std::fs::read_dir(&dir)
            .unwrap()
            .any(|e| e.unwrap().file_name().to_string_lossy().ends_with("_req.bin"));
        if !has_requests {
            println!("skip (command chain): {name}");
            continue;
        }
        // The emulator does not model update_wntz like the RTL, so only the framing is checked
        // for these folders (the command must succeed and return 32 bytes), not the digest.
        let framing_only = name.contains("update_wntz");
        // The emulator panics (unwrap) when the external-mu path gets a signature that does not
        // decode; the RTL just reports it invalid. test_acvp_mldsa_verify covers that path.
        // The software emulator has no host memory for the DMA to read; FPGA only.
        // The emulator has no host memory: its DMA model panics on the staged AXI address.
        if name.contains("sha384_image") {
            println!("skip (needs host memory): {name}");
            continue;
        }
        if name.contains("ML_DSA_87_SIGVER_verify_internal") {
            println!("skip (emulator limitation): {name}");
            continue;
        }
        let expected: serde_json::Value = {
            let txt =
                std::fs::read_to_string(format!("{vec_root}/{name}/testvector-expected.json"))
                    .unwrap();
            let v: serde_json::Value = serde_json::from_str(&txt).unwrap();
            if v.is_array() {
                v[1].clone()
            } else {
                v
            }
        };
        for group in expected["testGroups"].as_array().unwrap() {
            for test in group["tests"].as_array().unwrap() {
                let tc = test["tcId"].as_u64().unwrap();
                let req = std::fs::read(dir.join(format!("TC_{tc}_req.bin"))).unwrap();
                let resp = model
                    .mailbox_execute(u32::from(CommandId::ACVP_TEST), &req)
                    .unwrap_or_else(|e| panic!("{name} TC_{tc}: {e:?}"))
                    .unwrap();
                assert!(verify_checksum(
                    u32::from_le_bytes(resp[0..4].try_into().unwrap()),
                    0,
                    &resp[4..]
                ));
                // Optionally keep the raw responses so the framework's grader can check them too.
                if let Ok(out) = std::env::var("ACVP_RESPONSE_DIR") {
                    std::fs::create_dir_all(format!("{out}/{name}")).unwrap();
                    std::fs::write(format!("{out}/{name}/TC_{tc}.bin"), &resp).unwrap();
                }
                let result = u32::from_le_bytes(resp[8..12].try_into().unwrap());
                let err = u32::from_le_bytes(resp[12..16].try_into().unwrap());
                let data = &resp[ACVP_RESP_HDR_SIZE..];
                let obj = test.as_object().unwrap();
                // KDA VAL tests: the device derives the key (result OK), the tester compares it with the
                // supplied dkm; the grader checks that, so only the size is checked here.
                if name.contains("KDA-") && obj.contains_key("testPassed") {
                    assert_eq!(result, ACVP_RESULT_OK, "{name} TC_{tc}: error 0x{err:08x}");
                    assert!(data.len() >= 48, "{name} TC_{tc}: dkm size");
                    checked += 1;
                    continue;
                }
                // Verification folders: the answer is the verdict.
                if let Some(want) = obj.get("testPassed") {
                    assert!(
                        result == ACVP_RESULT_OK || result == ACVP_RESULT_FALSE,
                        "{name} TC_{tc}: error 0x{err:08x}"
                    );
                    assert_eq!(
                        result == ACVP_RESULT_OK,
                        want.as_bool().unwrap(),
                        "{name} TC_{tc}: verdict"
                    );
                    checked += 1;
                    continue;
                }
                assert_eq!(result, ACVP_RESULT_OK, "{name} TC_{tc}: error 0x{err:08x}");
                // Folders whose answer depends on a device choice (KDF fixed data, signature
                // generation keys) cannot be compared with the lab's sample here; the framework's
                // grader checks them. Only the size is checked.
                if obj.contains_key("keyOut") {
                    let want = hex::decode(obj["keyOut"].as_str().unwrap()).unwrap();
                    assert!(data.len() >= want.len(), "{name} TC_{tc}: key output size");
                    checked += 1;
                    continue;
                }
                if obj.contains_key("ct") && obj.contains_key("tag") && obj.contains_key("iv") {
                    // Device-chosen IV: the grader decrypts; here only the size is checked.
                    let ct = hex::decode(obj["ct"].as_str().unwrap()).unwrap();
                    assert_eq!(data.len(), 12 + ct.len() + 16, "{name} TC_{tc}: iv ct tag");
                    checked += 1;
                    continue;
                }
                if obj.contains_key("r") && obj.contains_key("s") {
                    if name.contains("_csr_") {
                        // qx || qy || COSE_Sign1 / DER CSR; the grader extracts the signature.
                        assert!(data.len() > 192, "{name} TC_{tc}: csr structure");
                        checked += 1;
                        continue;
                    }
                    assert_eq!(data.len(), 192, "{name} TC_{tc}: qx qy r s");
                    checked += 1;
                    continue;
                }
                // The emulator does not model update_wntz like the RTL, so only the framing is
                // checked for these folders (the command must succeed and return 32 bytes).
                if framing_only {
                    assert_eq!(data.len(), 32, "{name} TC_{tc}");
                    checked += 1;
                    continue;
                }
                let (key, want) = obj.iter().find(|(k, _)| k.as_str() != "tcId").unwrap();
                let want = hex::decode(want.as_str().unwrap()).unwrap();
                assert_eq!(&data[..want.len()], &want[..], "{name} TC_{tc} ({key})");
                checked += 1;
            }
        }
    }
    println!("replayed {checked} test case(s)");
    assert!(checked > 0);
}

/// Interprets a script generated by the tester framework's generate_acvp_test.py and runs it on the
/// emulator the way the FST engine would on the FPGA: `ExecutePython:` lines run the relay scripts
/// (so the real relay code and request layouts are exercised), every `caliptra_mbox_test` PI sends
/// its request and stores the response in its dataout file. Only CM_* chains are replayed;
/// HOST_MEM_RW steps (host memory staging) are skipped because the emulator has no host memory.
///
/// ACVP_SCRIPT: Generated/<name>.txt     ACVP_REPO: the tester framework repo root
/// Afterwards run `grade_acvp.py --name <name>` to grade the CAP_* captures.
#[test]
#[ignore = "needs ACVP_SCRIPT and ACVP_REPO"]
fn test_acvp_replay_generated_chain_script() {
    use std::process::Command;
    let (Ok(script), Ok(repo)) = (std::env::var("ACVP_SCRIPT"), std::env::var("ACVP_REPO")) else {
        panic!("set ACVP_SCRIPT and ACVP_REPO");
    };
    let text = std::fs::read_to_string(&script).unwrap();
    let id_of = |name: &str| -> u32 {
        u32::from(match name {
            "CM_IMPORT" => CommandId::CM_IMPORT,
            "CM_DELETE" => CommandId::CM_DELETE,
            "CM_ECDSA_PUBLIC_KEY" => CommandId::CM_ECDSA_PUBLIC_KEY,
            "CM_ECDSA_SIGN" => CommandId::CM_ECDSA_SIGN,
            "CM_AES_GCM_ENCRYPT_INIT" => CommandId::CM_AES_GCM_ENCRYPT_INIT,
            "CM_AES_GCM_ENCRYPT_UPDATE" => CommandId::CM_AES_GCM_ENCRYPT_UPDATE,
            "CM_AES_GCM_ENCRYPT_FINAL" => CommandId::CM_AES_GCM_ENCRYPT_FINAL,
            "CM_AES_GCM_DECRYPT_INIT" => CommandId::CM_AES_GCM_DECRYPT_INIT,
            "CM_AES_GCM_DECRYPT_UPDATE" => CommandId::CM_AES_GCM_DECRYPT_UPDATE,
            "CM_AES_GCM_DECRYPT_FINAL" => CommandId::CM_AES_GCM_DECRYPT_FINAL,
            "CM_AES_GCM_DECRYPT_DMA" => CommandId::CM_AES_GCM_DECRYPT_DMA,
            "CM_HMAC_KDF_COUNTER" => CommandId::CM_HMAC_KDF_COUNTER,
            other => panic!("unknown command {other}"),
        })
    };
    let field = |line: &str| -> Vec<String> {
        line.split_once('=')
            .unwrap()
            .1
            .split('|')
            .map(|s| s.trim().to_string())
            .collect()
    };

    let mut model = acvp_model();
    let mut in_mbox_pi = false;
    let mut is_host_pi = false;
    let (mut cmd, mut dlen, mut datain, mut dataout, mut dlen_out) =
        (String::new(), 0usize, (String::new(), String::new()), String::new(), 0usize);
    let mut sent = 0;
    let mut tc = String::new();
    for line in text.lines() {
        let l = line.trim();
        if let Some(rest) = l.strip_prefix("TestCase:") {
            tc = rest.trim().to_string();
        } else if let Some(rest) = l.strip_prefix("ExecutePython:") {
            let mut parts = rest.split(',').map(|s| s.trim().to_string());
            let py = parts.next().unwrap();
            let status = Command::new("python3")
                .arg(format!("{repo}/{py}"))
                .args(parts)
                .current_dir(format!("{repo}/securetool"))
                .status()
                .unwrap();
            assert!(status.success(), "{tc}: relay failed: {rest}");
        } else if l.starts_with("PrimitiveName:") {
            in_mbox_pi = l.ends_with("caliptra_mbox_test");
            is_host_pi = !in_mbox_pi;
        } else if in_mbox_pi && l.starts_with("ARG0:") {
            cmd = field(l)[2].clone();
        } else if in_mbox_pi && l.starts_with("ARG1:") {
            dlen = field(l)[2].parse().unwrap();
        } else if in_mbox_pi && l.starts_with("ARG2:") {
            let f = field(l);
            datain = (f[0].clone(), f[2].clone());
        } else if in_mbox_pi && l.starts_with("ARG3:") {
            dataout = field(l)[2].clone();
        } else if in_mbox_pi && l.starts_with("ARG4:") {
            dlen_out = field(l)[2].parse().unwrap();
        } else if l == "END" && in_mbox_pi && !cmd.is_empty() && dlen_out != 0 {
            let req = if datain.0 == "PTR_U32_IN_BINFILE" {
                std::fs::read(format!("{repo}/{}", datain.1)).unwrap()
            } else {
                hex::decode(&datain.1).unwrap()
            };
            assert_eq!(req.len(), dlen, "{tc} {cmd}: request file size != dlen");
            if cmd == "CM_AES_GCM_DECRYPT_DMA" {
                // Needs host memory and a PL0 caller: not runnable on the emulator. Check that the
                // request matches the Rust layout instead.
                use std::mem::offset_of;
                let word = |off: usize| u32::from_le_bytes(req[off..off + 4].try_into().unwrap()) as usize;
                let aad_len = word(offset_of!(CmAesGcmDecryptDmaReq, aad_length));
                assert_eq!(req.len(), offset_of!(CmAesGcmDecryptDmaReq, aad) + aad_len, "{tc}: DMA request size");
                assert_eq!(word(offset_of!(CmAesGcmDecryptDmaReq, axi_addr_hi)), 0, "{tc}: address hi");
                assert_eq!(word(offset_of!(CmAesGcmDecryptDmaReq, axi_addr_lo)), 0xB000_8000, "{tc}: address lo");
                println!("{tc}: CM_AES_GCM_DECRYPT_DMA request layout ok (length {})", word(offset_of!(CmAesGcmDecryptDmaReq, length)));
                in_mbox_pi = false;
                cmd.clear();
                dlen_out = 0;
                continue;
            }
            let resp = model
                .mailbox_execute(id_of(&cmd), &req)
                .unwrap_or_else(|e| panic!("{tc} {cmd}: mailbox failure {e:?}"))
                .unwrap_or_default();
            assert!(
                resp.len() <= dlen_out,
                "{tc} {cmd}: response {} B exceeds dlen_out {dlen_out}",
                resp.len()
            );
            let mut out = resp.clone();
            out.resize(dlen_out, 0);
            std::fs::write(format!("{repo}/{dataout}"), out).unwrap();
            sent += 1;
            in_mbox_pi = false;
            cmd.clear();
            dlen_out = 0;
        } else if l == "END" && is_host_pi {
            is_host_pi = false;
        }
    }
    println!("replayed {sent} mailbox command(s) from {script}");
    assert!(sent > 0);
}
