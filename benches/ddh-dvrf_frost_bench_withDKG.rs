use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId, black_box};
use frost_secp256k1_evm::rand_core::OsRng;
use frostlab::dkg::{DkgConfig, run_dealerless_dkg};
use frostlab::ddh_dvrf::run_ddh_dvrf_once;
use frostlab::frost_ext::{frost_sign, frost_verify};

fn bench_full_protocol(c: &mut Criterion) {
    let mut group = c.benchmark_group("Full protocol benchmarks");
    let configs = vec![(5, 3), (9, 5), (13, 7), (19, 10), (29, 15), (39, 20), (59, 30), (99, 50)];

    for (n, t) in configs {
        group.bench_with_input(BenchmarkId::new("DKG+DDH+FROST", format!("n={n},t={t}")), &(n, t), |b, &(n, t)| {
            b.iter(|| {
                let mut rng = OsRng;
                let cfg = DkgConfig::new(n, t).unwrap();
                let out = run_dealerless_dkg(cfg, &mut rng).unwrap();
                let all_ids = out.all_ids();
                let msg_dvrf = b"dvrfddhhello";
                let signers = &all_ids[..cfg.min_signers as usize];
                let (_v, _points) = run_ddh_dvrf_once(
                    msg_dvrf,
                    &out.key_packages,
                    &out.public_key_package,
                    signers,
                );
                let msg_frost = b"attestation";
                let sig = frost_sign(msg_frost, &out, signers, &mut rng).unwrap();
                let ok = frost_verify(msg_frost, &sig, &out).unwrap();
                assert!(ok);
                black_box(ok);
            })
        });
    }

    group.finish();
}

criterion_group!(benches, bench_full_protocol);
criterion_main!(benches);
