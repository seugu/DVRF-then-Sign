use std::u16;

use anyhow::Result;
use frost_secp256k1_evm::rand_core::OsRng;
use k256::elliptic_curve::group::GroupEncoding;

use frostlab::dkg::{DkgConfig, run_dealerless_dkg, DkgOutput};
use frostlab::ddh_dvrf::{run_ddh_dvrf_once, id_as_u64};
use frostlab::utils::hash_to_curve_point_keccak;
use frostlab::frost_ext::{frost_sign, frost_verify};

fn run_single_ddh_dvrf(msg: &[u8], out: &DkgOutput, signer_count: usize) -> Result<()> {
    let all_ids = out.all_ids();

    if signer_count == 0 || signer_count > all_ids.len() {
        anyhow::bail!("invalid signer_count: {}", signer_count);
    }

    let signers = &all_ids[..signer_count];

    // DDH-DVRF run
    let (v, points) = run_ddh_dvrf_once(msg, &out.key_packages, &out.public_key_package, signers);

    println!("\n─── DDH-DVRF Execution ───");
    println!(
        "PH(msg) compressed: 0x{}",
        hex::encode(k256::AffinePoint::from(hash_to_curve_point_keccak(msg)).to_bytes())
    );
    println!(
        "v (combined) compressed: 0x{}",
        hex::encode(k256::AffinePoint::from(v).to_bytes())
    );

    for (id, vi) in points {
        println!(
            "id={}  v_{}: 0x{}",
            id_as_u64(id),
            id_as_u64(id),
            hex::encode(k256::AffinePoint::from(vi).to_bytes())
        );
    }

    Ok(())
}

fn ddh_and_frost_main(max: u16, min: u16) -> Result<()> {
    // DKG 
    let mut rng = OsRng;
    let cfg = DkgConfig::new(max, min)?;
    let out = run_dealerless_dkg(cfg, &mut rng)?;
    println!("─── DKG completed: {} of {} threshold ───", min, max);

    // DVRF
    let msg_dvrf = b"dvrfddhhello";
    run_single_ddh_dvrf(msg_dvrf, &out, cfg.min_signers as usize)?;

    // FROST Signing (attestation)
    let msg_frost = b"attestation";
    let all_ids = out.all_ids();
    let signers = &all_ids[..cfg.min_signers as usize];

    println!("\n─── FROST signing on message: \"{}\" ───", String::from_utf8_lossy(msg_frost));
    let sig = frost_sign(msg_frost, &out, signers, &mut rng)?;

    // Verify FROST signature
    let ok = frost_verify(msg_frost, &sig, &out)?;
    println!("FROST signature valid: {}", ok);
    assert!(ok);

    Ok(())
}



fn main() -> Result<()> {
    // example 5 out of 4
    ddh_and_frost_main(5, 4)
}
