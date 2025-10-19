//! Dealerless JF-DKG wrapper (secp256k1, EVM ciphersuite).

use std::collections::BTreeMap;
use anyhow::{bail, Result};
use frost_secp256k1_evm as frost;

use frost::rand_core::{CryptoRng, RngCore};

pub type Identifier = frost::Identifier;
pub type KeyPackage = frost::keys::KeyPackage;
pub type PublicKeyPackage = frost::keys::PublicKeyPackage;

/// DKG config
#[derive(Clone, Copy, Debug)]
pub struct DkgConfig {
    pub max_signers: u16,
    pub min_signers: u16,
}

impl DkgConfig {
    pub fn new(max_signers: u16, min_signers: u16) -> Result<Self> {
        if max_signers < 2 { bail!("max_signers must be >= 2"); }
        if min_signers < 2 { bail!("min_signers must be >= 2"); }
        if min_signers > max_signers { bail!("min_signers must be <= max_signers"); }
        Ok(Self { max_signers, min_signers })
    }
}

/// DKG output
pub struct DkgOutput {
    pub key_packages: BTreeMap<Identifier, KeyPackage>,
    pub public_key_package: PublicKeyPackage,
}

impl DkgOutput {
    pub fn all_ids(&self) -> Vec<Identifier> {
        let mut v: Vec<_> = self.key_packages.keys().copied().collect();
        v.sort();
        v
    }
}

/// Local DKG
pub fn run_dealerless_dkg<R: RngCore + CryptoRng>(cfg: DkgConfig, rng: &mut R) -> Result<DkgOutput> {
    let n = cfg.max_signers;
    let t = cfg.min_signers;

    // --- Round 1: herkes kendi Part1 secret'ını ve broadcast paketini üretir.
    let mut round1_secret = BTreeMap::<Identifier, _>::new();
    let mut recv_r1_pkgs  = BTreeMap::<Identifier, BTreeMap<Identifier, _>>::new();

    for i in 1..=n {
        let id: Identifier = i.try_into().expect("nonzero id");
        let (r1_secret, r1_pkg) = frost::keys::dkg::part1(id, n, t, &mut *rng)?;
        round1_secret.insert(id, r1_secret);

        for j in 1..=n {
            if j == i { continue; }
            let rid: Identifier = j.try_into().unwrap();
            recv_r1_pkgs.entry(rid)
                .or_insert_with(BTreeMap::new)
                .insert(id, r1_pkg.clone());
        }
    }

    // --- Round 2
    let mut round2_secret = BTreeMap::<Identifier, _>::new();
    let mut recv_r2_pkgs  = BTreeMap::<Identifier, BTreeMap<Identifier, _>>::new();

    for i in 1..=n {
        let id: Identifier = i.try_into().unwrap();
        let r1_secret = round1_secret.remove(&id).expect("r1 secret");
        let r1_pkgs   = &recv_r1_pkgs[&id];

        let (r2_secret, r2_pkgs) = frost::keys::dkg::part2(r1_secret, r1_pkgs)?;
        round2_secret.insert(id, r2_secret);


        for (recv_id, r2_pkg) in r2_pkgs {
            recv_r2_pkgs.entry(recv_id)
                .or_insert_with(BTreeMap::new)
                .insert(id, r2_pkg);
        }
    }

    // --- Round 3 
    let mut key_packages = BTreeMap::<Identifier, KeyPackage>::new();
    let mut pubkey_pkg_opt: Option<PublicKeyPackage> = None;

    for i in 1..=n {
        let id: Identifier = i.try_into().unwrap();
        let r2_secret = &round2_secret[&id];
        let r1_pkgs   = &recv_r1_pkgs[&id];
        let r2_pkgs   = &recv_r2_pkgs[&id];

        let (kp, pkpkg) = frost::keys::dkg::part3(r2_secret, r1_pkgs, r2_pkgs)?;
        key_packages.insert(id, kp);

        if pubkey_pkg_opt.is_none() {
            pubkey_pkg_opt = Some(pkpkg);
        }
    }

    let public_key_package = pubkey_pkg_opt.expect("same across participants");
    Ok(DkgOutput { key_packages, public_key_package })
}


#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use frost_secp256k1_evm::rand_core::OsRng;

    #[test]
    fn test_dkg() -> Result<()> {
    let mut rng = OsRng;
    let cfg = DkgConfig::new(3, 2)?;
    let out = run_dealerless_dkg(cfg, &mut rng)?;
    println!("Group verifying key:\n{:?}", out.key_packages);
    println!("DKG module resolved and ran ✅");
    Ok(())
    }
}
