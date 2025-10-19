use std::collections::BTreeMap;

use frost_secp256k1_evm as frost;

use k256::{
    Scalar, ProjectivePoint, Secp256k1,
    elliptic_curve::{ops::Reduce, FieldBytes, bigint::U256},
};

use crate::utils::{prove_eq, verify_eq, lagrange_combine_points};

pub type Identifier        = frost::Identifier;
pub type KeyPackage        = frost::keys::KeyPackage;
pub type PublicKeyPackage  = frost::keys::PublicKeyPackage;



/// Convert secret share) in KeyPackage to k256::Scalar
pub fn scalar_from_keypackage(kk: &KeyPackage) -> Scalar {
    let ser = kk.signing_share().serialize();    
    let mut bytes32 = [0u8; 32];
    bytes32.copy_from_slice(&ser);

    let fb: FieldBytes<Secp256k1> = bytes32.into();
    <Scalar as Reduce<U256>>::reduce_bytes(&fb)
}

/// Retrieve each participant’s public share (vk_i) from the PublicKeyPackage → k256 Point
pub fn vk_share_from_public_pkg(pkpkg: &PublicKeyPackage, id: Identifier) -> ProjectivePoint {
    // Common API pattern: either `verifying_key_shares()` map or `verifying_key_share(id)`.
    // I’m showing both variants; keep whichever line matches your implementation.
    let vk_share = pkpkg
        .verifying_shares()
        .get(&id)
        .expect("verifying key share for id");
    // let vk_share = pkpkg.verifying_key_share(id).expect("verifying key share for id");

    // `vk_share` is usually the native type of the curve point; in most versions,
    let point = vk_share.to_element();
    // If `into()` is available: let point: ProjectivePoint = vk_share.into();

    point
}


pub fn id_as_u64(id: Identifier) -> u64 {
    let bytes = id.serialize();
    let mut arr = [0u8; 8];
    arr.copy_from_slice(&bytes[24..32]);
    u64::from_be_bytes(arr)
}


/// Single-message DDH-DVRF round:
/// - For the selected signers I (size ≥ t), each signer produces (v_i, π_i)
/// - Each π_i is verified
/// - The values are combined using LagrangeCombine({(i, v_i)}) to obtain v
pub fn run_ddh_dvrf_once(
    msg: &[u8],
    key_packages: &BTreeMap<Identifier, KeyPackage>,
    public_key_package: &PublicKeyPackage,
    signers: &[Identifier],   //  (t-of-n)
) -> (ProjectivePoint, Vec<(Identifier, ProjectivePoint)>) {

    
    let mut good_points: Vec<(u64, ProjectivePoint)> = Vec::new();
    let mut exported_points_for_debug: Vec<(Identifier, ProjectivePoint)> = Vec::new();

    for id in signers {
        let kp = key_packages.get(id).expect("id has KeyPackage");
        let sk_i = scalar_from_keypackage(kp);
        let vk_i = vk_share_from_public_pkg(public_key_package, *id);

        let (v_i, proof) = prove_eq(msg, vk_i, sk_i);

        // kanıtı kontrol et
        let ok = verify_eq(msg, &vk_i, &v_i, &proof);
        assert!(ok, "prove_eq / verify_eq failed for id={}", id_as_u64(*id));

        good_points.push((id_as_u64(*id), v_i));
        exported_points_for_debug.push((*id, v_i));
    }

    // 2) Lagrange combine: v = Σ λ_i * v_i   (additive form)
    let v = lagrange_combine_points(&good_points);

    (v, exported_points_for_debug)
}
