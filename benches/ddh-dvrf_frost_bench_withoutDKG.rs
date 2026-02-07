use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId, black_box};
use frost_secp256k1_evm::rand_core::OsRng;
use frostlab::dkg::{DkgConfig, run_dealerless_dkg};
use frostlab::ddh_dvrf::run_ddh_dvrf_once;
use frostlab::frost_ext::{frost_sign, frost_verify};

fn bench_post_dkg(c: &mut Criterion) {
    let mut group = c.benchmark_group("Post-DKG protocol benchmarks");
    let configs = vec![
        (5, 3), (9, 5), (13, 7), (19, 10),
        (29, 15), (39, 20), (59, 30), (99, 50)
    ];

    for (n, t) in configs {
        // DKG'yi sadece bir kere yapıyoruz — benchmark dışı.
        let mut rng = OsRng;
        let cfg = DkgConfig::new(n, t).unwrap();
        let out = run_dealerless_dkg(cfg.clone(), &mut rng).unwrap();

        // DKG sonuçlarından gerekli verileri çıkarıyoruz
        let all_ids = out.all_ids();
        let signers = &all_ids[..cfg.min_signers as usize];
        let msg_dvrf = b"dvrfddhhello";
        let msg_frost = b"attestation";

        group.bench_with_input(BenchmarkId::new("DDH+FROST", format!("n={n},t={t}")), &(n, t), |b, _| {
            b.iter(|| {
                // DKG hariç DVRF + FROST işlemleri
                let (_v, _points) = run_ddh_dvrf_once(
                    msg_dvrf,
                    &out.key_packages,
                    &out.public_key_package,
                    signers,
                );
                let sig = frost_sign(msg_frost, &out, signers, &mut OsRng).unwrap();
                let ok = frost_verify(msg_frost, &sig, &out).unwrap();
                assert!(ok);
                black_box(ok);
            })
        });
    }

    group.finish();
}

criterion_group!(benches, bench_post_dkg);
criterion_main!(benches);
