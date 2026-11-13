// Licensed under the Apache-2.0 license

//! Test-only key setter for the `ACVP_TEST` cryptographic-mailbox targets.
//!
//! `CmStorage` keeps the KEK and the context key private and fills them from the key vault and
//! the TRNG. To run the private `encrypt_*` functions against a known-answer key, this child
//! module (which can see the private items of its parent) installs the vector key and then calls
//! the unchanged production function.

use super::*;

/// Which private encrypt function to run.
#[derive(Clone, Copy)]
pub(crate) enum Kind {
    Cmk,
    AesContext,
    AesGcmContext,
    EcdhContext,
    Shake256Context,
}

impl CmStorage {
    /// Installs `key` as both the KEK and the context key (second share zero, so the effective key
    /// is `key`) and starts the GCM IV counters at fresh random values like `init()` does.
    fn acvp_install_key(&mut self, trng: &mut Trng, key: LEArray4x8) -> CaliptraResult<()> {
        let kek_iv = trng.generate4()?;
        self.kek_next_iv = (((kek_iv.0 & 0x7fff_ffff) as u128) << 64)
            | ((kek_iv.1 as u128) << 32)
            | (kek_iv.2 as u128);
        let ctx_iv = trng.generate4()?;
        self.context_next_iv = (((ctx_iv.0 & 0x7fff_ffff) as u128) << 64)
            | ((ctx_iv.1 as u128) << 32)
            | (ctx_iv.2 as u128);
        self.kek = (key.clone(), LEArray4x8::default());
        self.context_key = (key, LEArray4x8::default());
        Ok(())
    }

    /// Encrypts `plaintext` with the selected private function under `key`.
    /// Writes `iv(12) || ciphertext || tag(16)` to `out` and returns its length.
    pub(crate) fn acvp_encrypt(
        &mut self,
        aes: &mut Aes,
        trng: &mut Trng,
        kind: Kind,
        key: LEArray4x8,
        plaintext: &[u8],
        out: &mut [u8],
    ) -> CaliptraResult<usize> {
        self.acvp_install_key(trng, key)?;
        let bad = || CaliptraError::RUNTIME_MAILBOX_INVALID_PARAMS;
        match kind {
            Kind::Cmk => {
                let cmk = UnencryptedCmk::read_from_bytes(plaintext).map_err(|_| bad())?;
                let e = self.encrypt_cmk(aes, trng, &cmk)?;
                pack(out, e.iv.as_bytes(), &e.ciphertext, e.gcm_tag.as_bytes())
            }
            Kind::AesContext => {
                let ctx = AesContext::read_from_bytes(plaintext).map_err(|_| bad())?;
                let e = self.encrypt_aes_context(aes, trng, &ctx)?;
                pack(out, e.iv.as_bytes(), &e.ciphertext, e.tag.as_bytes())
            }
            Kind::AesGcmContext => {
                let ctx = AesGcmContext::read_from_bytes(plaintext).map_err(|_| bad())?;
                let e = self.encrypt_aes_gcm_context(aes, trng, &ctx)?;
                pack(out, e.iv.as_bytes(), &e.ciphertext, e.tag.as_bytes())
            }
            Kind::EcdhContext => {
                let ctx: [u8; CMB_ECDH_CONTEXT_SIZE] = plaintext.try_into().map_err(|_| bad())?;
                let e = self.encrypt_ecdh_context(aes, trng, &ctx)?;
                pack(out, e.iv.as_bytes(), &e.ciphertext, e.tag.as_bytes())
            }
            Kind::Shake256Context => {
                let token: [u8; 16] = plaintext.try_into().map_err(|_| bad())?;
                let e = self.encrypt_shake256_context(aes, trng, u128::from_le_bytes(token))?;
                pack(out, e.iv.as_bytes(), &e.ciphertext, e.tag.as_bytes())
            }
        }
    }
}

fn pack(out: &mut [u8], iv: &[u8], ct: &[u8], tag: &[u8]) -> CaliptraResult<usize> {
    let total = iv.len() + ct.len() + tag.len();
    let dst = out
        .get_mut(..total)
        .ok_or(CaliptraError::RUNTIME_INSUFFICIENT_MEMORY)?;
    let (d_iv, rest) = dst.split_at_mut(iv.len());
    let (d_ct, d_tag) = rest.split_at_mut(ct.len());
    d_iv.copy_from_slice(iv);
    d_ct.copy_from_slice(ct);
    d_tag.copy_from_slice(tag);
    Ok(total)
}
