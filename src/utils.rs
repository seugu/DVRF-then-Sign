use k256::{
    Scalar, Secp256k1, ProjectivePoint,
    elliptic_curve::{ops::Reduce, FieldBytes, bigint::U256},
};
use tiny_keccak::{Hasher, Keccak};

use k256::{
    AffinePoint,
    elliptic_curve::{group::GroupEncoding},
};
use rand::rngs::OsRng;

/// Keccak256 hash fonksiyonu
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut h = Keccak::v256();
    h.update(data);
    let mut out = [0u8; 32];
    h.finalize(&mut out);
    out
}

/// Mesajı scalar’a (mod r) indirger
pub fn hash_to_scalar_keccak(data: &[u8]) -> Scalar {
    let digest = keccak256(data);
    let fb: FieldBytes<Secp256k1> = digest.into();
    <Scalar as Reduce<U256>>::reduce_bytes(&fb)
}

pub fn hash_to_curve_point_keccak(data: &[u8]) -> ProjectivePoint {
    let s = hash_to_scalar_keccak(data);
    ProjectivePoint::GENERATOR * s
}

pub fn lagrange_combine_points(points: &[(u64, ProjectivePoint)]) -> ProjectivePoint {
    let ids: Vec<u64> = points.iter().map(|(id, _)| *id).collect();
    let mut result = ProjectivePoint::IDENTITY;

    for (i, p_i) in points.iter() {
        let mut num = Scalar::ONE;
        let mut den = Scalar::ONE;

        for j in &ids {
            if i != j {
                num *= Scalar::from(*j);
                den *= Scalar::from(*j) - Scalar::from(*i);
            }
        }

        let lambda_i = num * den.invert().unwrap();
        result += *p_i * lambda_i;
    }

    result
}




/// Sıkıştırılmış (SEC1) nokta baytları
#[inline]
fn point_bytes_compressed(p: &ProjectivePoint) -> [u8; 33] {
    let enc = AffinePoint::from(*p).to_bytes();
    let mut out = [0u8; 33];
    out.copy_from_slice(enc.as_ref());
    out
}

/// Challenge = Keccak(G || PH || vk || v || com1 || com2) mod r
pub fn challenge_keccak(
    g: &ProjectivePoint,
    ph: &ProjectivePoint,
    vk: &ProjectivePoint,
    v:  &ProjectivePoint,
    com1: &ProjectivePoint,
    com2: &ProjectivePoint,
) -> Scalar {
    let mut k = Keccak::v256();
    for pp in [g, ph, vk, v, com1, com2] {
        k.update(&point_bytes_compressed(pp));
    }
    let mut out = [0u8; 32];
    k.finalize(&mut out);
    // reduce mod r
    let fb: FieldBytes<Secp256k1> = out.into();
    <Scalar as Reduce<U256>>::reduce_bytes(&fb)
}

/// Prova çıktısı (π_i)
#[derive(Clone, Copy, Debug)]
pub struct Proof {
    pub ch: Scalar, // pi_i_1
    pub rs: Scalar, // pi_i_2
}

/// proveEq(G, m, vk_i, sk_i) -> (v_i, pi_i)
///
/// - PH = H(m) (hash_to_curve_point_keccak)
/// - v_i = PH * sk_i
/// - r  ~ U(Z_r)
/// - com1 = G  * r
/// - com2 = PH * r
/// - ch   = Keccak(G, PH, vk_i, v_i, com1, com2) mod r
/// - rs   = sk_i * ch + r
pub fn prove_eq(
    msg: &[u8],
    vk_i: ProjectivePoint,  // DKG'den gelen public (G*sk_i)
    sk_i: Scalar,           // DKG'den gelen secret
) -> (ProjectivePoint, Proof) {
    let g  = ProjectivePoint::GENERATOR;
    let ph = hash_to_curve_point_keccak(msg);

    // partialEval: v_i = sk_i * PH
    let v_i = ph * sk_i;

    // nonce r
    let r = Scalar::generate_biased(&mut OsRng); // veya generate_vartime(&mut OsRng)

    // taahhütler
    let com1 = g  * r;
    let com2 = ph * r;

    // challenge
    let ch = challenge_keccak(&g, &ph, &vk_i, &v_i, &com1, &com2);
    // response
    let rs = (sk_i * ch) + r;

    (v_i, Proof { ch, rs })
}

/// verifyEq(G, PH, vk_i, v_i, pi_i)
/// com1' = (G * rs)  + (vk_i * -ch)
/// com2' = (PH * rs) + (v_i  * -ch)
/// Keccak(G,PH,vk_i,v_i,com1',com2') ?= ch
pub fn verify_eq(
    msg: &[u8],
    vk_i: &ProjectivePoint,
    v_i:  &ProjectivePoint,
    pi:   &Proof,
) -> bool {
    let g  = ProjectivePoint::GENERATOR;
    let ph = hash_to_curve_point_keccak(msg);

    let minus_ch = Scalar::ZERO - pi.ch;

    let com1_p = (g  * pi.rs) + (*vk_i * minus_ch);
    let com2_p = (ph * pi.rs) + (*v_i  * minus_ch);

    let ch2 = challenge_keccak(&g, &ph, vk_i, v_i, &com1_p, &com2_p);
    ch2 == pi.ch
}


use std::fs::File;
use std::io::Write;
use serde::Serialize;
use sha3::{Digest, Keccak256};
use k256::ecdsa::{Signature, VerifyingKey};

#[derive(Serialize)]
pub struct FrostVerificationInput {
    pub message_hash: String,
    pub signature: String,
    pub expected_signer: String,
}

pub fn export_verification_input(
    sig: &Signature,
    vk: &VerifyingKey,
    msg: &[u8],
) -> std::io::Result<()> {
    let msg_hash = Keccak256::digest(msg);
    let pub_bytes = vk.to_encoded_point(false);
    let hash = Keccak256::digest(&pub_bytes.as_bytes()[1..]);
    let eth_addr = &hash[12..];

    let data = FrostVerificationInput {
        message_hash: format!("0x{}", hex::encode(msg_hash)),
        signature: format!("0x{}", hex::encode(sig.to_bytes())),
        expected_signer: format!("0x{}", hex::encode(eth_addr)),
    };

    let mut file = File::create("frost_verification_input.json")?;
    file.write_all(serde_json::to_string_pretty(&data)?.as_bytes())?;
    Ok(())
}


#[cfg(test)]
mod tests {
    use super::*;
    use k256::{AffinePoint, ProjectivePoint, Scalar};
    use k256::{
    elliptic_curve::{
        group::GroupEncoding,
             // <-- generic parametre: Integer = U256
    }, 
};

    #[test]
    fn test_lagrange_combine_points() {
        // f(x) = 3x + 5  =>  f(0)=5
        let shares = [
            (1u64, Scalar::from(8u64)),
            (2u64, Scalar::from(11u64)),
            (3u64, Scalar::from(14u64)),
        ];

        // v_i = G * f(i)
        let points: Vec<(u64, ProjectivePoint)> = shares
            .iter()
            .map(|(i, yi)| (*i, ProjectivePoint::GENERATOR * *yi))
            .collect();

        // Lagrange combine
        let v = lagrange_combine_points(&points);

        // Beklenen: G * 5
        let expected = ProjectivePoint::GENERATOR * Scalar::from(5u64);

        assert_eq!(v, expected, "Lagrange combine result is incorrect");

        println!("v (compressed):      0x{}", hex::encode(AffinePoint::from(v).to_bytes()));
        println!("G*5 (compressed):    0x{}", hex::encode(AffinePoint::from(expected).to_bytes()));
    }
    #[test]
    fn test_hash_to_map() {
    let msg = b"hello world";

    let s = hash_to_scalar_keccak(msg);
    let p = hash_to_curve_point_keccak(msg);

    println!("Scalar mod r: {:?}", s);
    println!("Curve point compressed: 0x{}", hex::encode(k256::AffinePoint::from(p).to_bytes()));
}

    #[test]
    fn test_prove_and_verify_EQ()
    {
    // sahte DKG çıktısı gibi: sk_i ve vk_i = G*sk_i
    let sk_i = Scalar::generate_biased(&mut OsRng);
    let vk_i = ProjectivePoint::GENERATOR * sk_i;

    let msg = b"hello FROST";

    let (v_i, proof) = prove_eq(msg, vk_i, sk_i);
    let ok = verify_eq(msg, &vk_i, &v_i, &proof);

    println!("verifyEq: {}", ok); // true
}


}
