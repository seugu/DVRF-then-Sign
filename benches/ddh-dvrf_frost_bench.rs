use criterion::{criterion_group, criterion_main, Criterion, black_box};
use frost_secp256k1_evm::rand_core::OsRng;

use frostlab::dkg::DkgConfig;
use frostlab::dkg::run_dealerless_dkg;
use frostlab::ddh_dvrf::{run_ddh_dvrf_once};
use frostlab::frost_ext::{frost_sign, frost_verify};

/// (DKG + DDH-DVRF + FROST sign/verify)
fn bench_full_protocol(c: &mut Criterion) {
    c.bench_function("Full protocol (DKG + DVRF + FROST)", |b| {
        b.iter(|| {
            let mut rng = OsRng;

            // 1️⃣ DKG setup
            let cfg = DkgConfig::new(5, 4).unwrap();
            let out = run_dealerless_dkg(cfg, &mut rng).unwrap();
            let all_ids = out.all_ids();

            // 2️⃣ DDH-DVRF
            let msg_dvrf = b"dvrfddhhello";
            let signers = &all_ids[..cfg.min_signers as usize];
            let (_v, _points) = run_ddh_dvrf_once(
                msg_dvrf,
                &out.key_packages,
                &out.public_key_package,
                signers,
            );

            // 3️⃣ FROST signing
            let msg_frost = b"attestation";
            let sig = frost_sign(msg_frost, &out, signers, &mut rng).unwrap();

            // 4️⃣ Verify
            let ok = frost_verify(msg_frost, &sig, &out).unwrap();
            assert!(ok);

            black_box(ok);
        })
    });
}

criterion_group!(benches, bench_full_protocol);
criterion_main!(benches);
