use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use frostlab::network_cost::{ProtocolCostSummary, DkgCost, DvrfCost, FrostTssCost};

/// Tek bir konfigürasyon için network cost hesapla
fn calculate_network_cost(max_signers: u16, min_signers: u16) -> ProtocolCostSummary {
    let mut summary = ProtocolCostSummary::new();
    
    // DKG cost
    let mut dkg = DkgCost::new(max_signers, min_signers);
    dkg.calculate_round1();
    dkg.calculate_round2();
    dkg.calculate_round3();
    summary.dkg_cost = Some(dkg);
    
    // DVRF cost (min_signers kadar participant)
    let mut dvrf = DvrfCost::new(min_signers);
    dvrf.calculate_evaluation();
    dvrf.calculate_verification();
    summary.dvrf_cost = Some(dvrf);
    
    // FROST TSS cost (min_signers kadar participant)
    let mut tss = FrostTssCost::new(min_signers);
    tss.calculate_round1_commitments();
    tss.calculate_round2_signatures();
    tss.calculate_aggregation();
    summary.tss_cost = Some(tss);
    
    summary
}

/// Benchmark: Farklı konfigürasyonlar için network cost hesaplama
fn network_cost_benchmark(c: &mut Criterion) {
    let configs = vec![
        (5, 3),
        (9, 5),
        (13, 7),
        (19, 10),
        (29, 15),
        (39, 20),
        (59, 30),
        (99, 50),
    ];

    let mut group = c.benchmark_group("network_cost_calculation");
    
    for (max, min) in configs.iter() {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}/{}", max, min)),
            &(*max, *min),
            |b, &(max_signers, min_signers)| {
                b.iter(|| {
                    calculate_network_cost(
                        black_box(max_signers),
                        black_box(min_signers)
                    )
                });
            },
        );
    }
    
    group.finish();
}

/// Detaylı cost analysis ve rapor çıktısı
fn detailed_cost_analysis(c: &mut Criterion) {
    let configs = vec![
        (5, 3),
        (9, 5),
        (13, 7),
        (19, 10),
        (29, 15),
        (39, 20),
        (59, 30),
        (99, 50),
    ];

    println!("\n╔═══════════════════════════════════════════════════════════════╗");
    println!("║          NETWORK COST ANALYSIS - TÜM KONFİGÜRASYONLAR         ║");
    println!("╚═══════════════════════════════════════════════════════════════╝\n");

    for (max, min) in configs.iter() {
        let summary = calculate_network_cost(*max, *min);
        
        println!("┌─────────────────────────────────────────────────────────────┐");
        println!("│ Konfigürasyon: {}-out-of-{} threshold", min, max);
        println!("└─────────────────────────────────────────────────────────────┘");
        println!("{}", summary.generate_report());
        
        // Detaylı breakdown
        if let Some(dkg) = &summary.dkg_cost {
            let total_dkg = dkg.total_cost();
            println!("📊 DKG Detayları:");
            println!("   ├─ Katılımcı başına ortalama: {:.2} KB", 
                total_dkg.total_bytes() as f64 / (*max as f64) / 1024.0);
            println!("   ├─ Round 1 (Commitment Broadcast): {:.2} KB", 
                dkg.round1_cost.total_bytes() as f64 / 1024.0);
            println!("   ├─ Round 2 (Share Distribution): {:.2} KB", 
                dkg.round2_cost.total_bytes() as f64 / 1024.0);
            println!("   └─ Round 3 (Verification): {:.2} KB\n", 
                dkg.round3_cost.total_bytes() as f64 / 1024.0);
        }
        
        if let Some(dvrf) = &summary.dvrf_cost {
            let total_dvrf = dvrf.total_cost();
            println!("🎲 DVRF Detayları:");
            println!("   ├─ Partial Evaluation başına: {:.2} bytes", 
                129.0); // 33 + 96
            println!("   ├─ İmzalayıcı başına ortalama: {:.2} KB", 
                total_dvrf.total_bytes() as f64 / (*min as f64) / 1024.0);
            println!("   └─ Verification overhead: {} mesaj\n", 
                dvrf.verification_cost.message_count);
        }
        
        if let Some(tss) = &summary.tss_cost {
            let total_tss = tss.total_cost();
            println!("✍️  FROST TSS Detayları:");
            println!("   ├─ Round 1 (Commitments): {:.2} KB", 
                tss.round1_commitment_cost.total_bytes() as f64 / 1024.0);
            println!("   ├─ Round 2 (Partial Sigs): {:.2} KB", 
                tss.round2_signature_cost.total_bytes() as f64 / 1024.0);
            println!("   ├─ İmzalayıcı başına ortalama: {:.2} KB", 
                total_tss.total_bytes() as f64 / (*min as f64) / 1024.0);
            println!("   └─ Final signature size: 64 bytes\n");
        }
        
        let total = summary.total_cost();
        println!("💰 TOPLAM MALİYET:");
        println!("   ├─ Toplam Bandwidth: {:.2} KB ({} bytes)", 
            total.total_bytes() as f64 / 1024.0, total.total_bytes());
        println!("   ├─ Toplam Mesaj: {}", total.message_count);
        println!("   ├─ Toplam Round: {}", total.round_count);
        println!("   └─ Katılımcı başına ort: {:.2} KB\n", 
            total.total_bytes() as f64 / (*max as f64) / 1024.0);
        
        println!("═══════════════════════════════════════════════════════════════\n");
    }

    // Karşılaştırmalı tablo
    println!("\n╔═══════════════════════════════════════════════════════════════╗");
    println!("║                  KARŞILAŞTIRMALI ÖZET TABLO                  ║");
    println!("╚═══════════════════════════════════════════════════════════════╝\n");
    
    println!("{:<12} | {:<15} | {:<15} | {:<15} | {:<12}", 
        "Config", "DKG (KB)", "DVRF (KB)", "TSS (KB)", "TOPLAM (KB)");
    println!("{:-<12}-+-{:-<15}-+-{:-<15}-+-{:-<15}-+-{:-<12}", "", "", "", "", "");
    
    for (max, min) in configs.iter() {
        let summary = calculate_network_cost(*max, *min);
        
        let dkg_kb = summary.dkg_cost.as_ref()
            .map(|d| d.total_cost().total_bytes() as f64 / 1024.0)
            .unwrap_or(0.0);
        
        let dvrf_kb = summary.dvrf_cost.as_ref()
            .map(|d| d.total_cost().total_bytes() as f64 / 1024.0)
            .unwrap_or(0.0);
        
        let tss_kb = summary.tss_cost.as_ref()
            .map(|t| t.total_cost().total_bytes() as f64 / 1024.0)
            .unwrap_or(0.0);
        
        let total_kb = summary.total_cost().total_bytes() as f64 / 1024.0;
        
        println!("{:<12} | {:<15.2} | {:<15.2} | {:<15.2} | {:<12.2}", 
            format!("{}/{}", max, min), dkg_kb, dvrf_kb, tss_kb, total_kb);
    }
    
    println!("\n");

    // Dummy benchmark (sadece rapor için)
    c.bench_function("detailed_analysis", |b| {
        b.iter(|| {
            black_box(calculate_network_cost(5, 3))
        })
    });
}

/// Scalability analizi
fn scalability_analysis(c: &mut Criterion) {
    let configs = vec![
        (5, 3),
        (9, 5),
        (13, 7),
        (19, 10),
        (29, 15),
        (39, 20),
        (59, 30),
        (99, 50),
    ];

    println!("\n╔═══════════════════════════════════════════════════════════════╗");
    println!("║              SCALABILITY ANALİZİ (Growth Metrics)             ║");
    println!("╚═══════════════════════════════════════════════════════════════╝\n");

    let mut prev_total: Option<f64> = None;
    
    println!("{:<12} | {:<15} | {:<20} | {:<15}", 
        "Config", "Total (KB)", "Growth vs Previous", "Per Participant");
    println!("{:-<12}-+-{:-<15}-+-{:-<20}-+-{:-<15}", "", "", "", "");
    
    for (max, min) in configs.iter() {
        let summary = calculate_network_cost(*max, *min);
        let total_kb = summary.total_cost().total_bytes() as f64 / 1024.0;
        let per_participant_kb = total_kb / (*max as f64);
        
        let growth = if let Some(prev) = prev_total {
            format!("{:.1}%", ((total_kb - prev) / prev) * 100.0)
        } else {
            "baseline".to_string()
        };
        
        println!("{:<12} | {:<15.2} | {:<20} | {:<15.2}", 
            format!("{}/{}", max, min), 
            total_kb, 
            growth,
            per_participant_kb);
        
        prev_total = Some(total_kb);
    }
    
    println!("\n");

    // Complexity analysis
    println!("📈 COMPLEXITY ANALİZİ:");
    println!("   DKG:  O(n²) - Her katılımcı herkesle iletişim kurar");
    println!("   DVRF: O(n)  - Broadcast based partial evaluations");
    println!("   TSS:  O(n)  - Threshold signature rounds\n");

    // Dummy benchmark
    c.bench_function("scalability_analysis", |b| {
        b.iter(|| {
            black_box(calculate_network_cost(5, 3))
        })
    });
}

criterion_group!(
    benches,
    network_cost_benchmark,
    detailed_cost_analysis,
    scalability_analysis
);

criterion_main!(benches);
