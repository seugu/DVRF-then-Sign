use std::collections::BTreeMap;
use anyhow::Result;
use frost_secp256k1_evm as frost;
use frost::rand_core::{CryptoRng, RngCore};
use frost::{round1, round2};
use crate::dkg::{DkgOutput, Identifier};

/// FROST signature
pub fn frost_sign<R: RngCore + CryptoRng>(
    msg: &[u8],
    out: &DkgOutput,
    signer_ids: &[Identifier],
    rng: &mut R,
) -> Result<frost::Signature> {
    // Round 1 — nonce and commitments
    let mut nonces_map = BTreeMap::new();
    let mut commits_map = BTreeMap::new();

    for id in signer_ids {
        let kp = out.key_packages.get(id).expect("KeyPackage exists");
        let (nonces, commitments) = round1::commit(kp.signing_share(), rng);
        nonces_map.insert(*id, nonces);
        commits_map.insert(*id, commitments);
    }

    // SigningPackage coordinator
    let signing_pkg = frost::SigningPackage::new(commits_map, msg);

    // Round 2 — partial sigs
    let mut sig_shares = BTreeMap::new();
    for (id, nonces) in &nonces_map {
        let kp = out.key_packages.get(id).expect("KeyPackage exists");
        let sig_share = round2::sign(&signing_pkg, nonces, kp)?;
        sig_shares.insert(*id, sig_share);
    }

    // Combine partials
    let group_sig = frost::aggregate(&signing_pkg, &sig_shares, &out.public_key_package)?;
    Ok(group_sig)
}

/// verify
pub fn frost_verify(msg: &[u8], sig: &frost::Signature, out: &DkgOutput) -> Result<bool> {
    let vk = out.public_key_package.verifying_key();
    let ok = vk.verify(msg, sig).is_ok();
    Ok(ok)
}

#[cfg(test)]
mod tests {
    use super::*;
    use frost_secp256k1_evm::rand_core::OsRng;
    use crate::dkg::{DkgConfig, run_dealerless_dkg};

    #[test]
    fn test_frost_sign_verify() -> Result<()> {
        let mut rng = OsRng;
        let cfg = DkgConfig::new(5, 3)?;
        let out = run_dealerless_dkg(cfg, &mut rng)?;
        let all_ids = out.all_ids();
        let signers = &all_ids[..cfg.min_signers as usize];

        let msg = b"attestation";

        // sign
        let sig = frost_sign(msg, &out, signers, &mut rng)?;

        // verify
        let ok = frost_verify(msg, &sig, &out)?;
        println!("FROST signature valid: {}", ok);
        assert!(ok);
        Ok(())
    }
}
