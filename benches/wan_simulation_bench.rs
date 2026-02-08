use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId};
use frostlab::network_cost::{ProtocolCostSummary, DkgCost, DvrfCost, FrostTssCost};

/// WAN network parameters
#[derive(Debug, Clone)]
struct WanParams {
    name: &'static str,
    one_way_latency_ms: f64,
    latency_jitter_ms: f64,
    bandwidth_mbps: f64,
    packet_loss_rate: f64,
}

impl WanParams {
    /// WAN1: 40ms ± 5ms one-way, 50 Mbps, 0.1% loss
    fn wan1() -> Self {
        Self {
            name: "WAN1",
            one_way_latency_ms: 40.0,
            latency_jitter_ms: 5.0,
            bandwidth_mbps: 50.0,
            packet_loss_rate: 0.001,
        }
    }

    /// WAN2: 75ms ± 15ms one-way, 20 Mbps, assumed 0.2% loss
    fn wan2() -> Self {
        Self {
            name: "WAN2",
            one_way_latency_ms: 75.0,
            latency_jitter_ms: 15.0,
            bandwidth_mbps: 20.0,
            packet_loss_rate: 0.002,
        }
    }

    /// Calculate Round-Trip Time (RTT) in milliseconds
    fn rtt_ms(&self) -> f64 {
        2.0 * self.one_way_latency_ms
    }

    /// Calculate transmission delay for given bytes
    fn transmission_delay_ms(&self, bytes: u64) -> f64 {
        let bits = (bytes * 8) as f64;
        let mbits = bits / 1_000_000.0;
        (mbits / self.bandwidth_mbps) * 1000.0
    }

    /// Calculate retransmission overhead due to packet loss
    fn retransmission_overhead(&self, message_count: u32) -> f64 {
        // Expected retransmissions = message_count * loss_rate
        // Each retransmission adds one RTT
        (message_count as f64) * self.packet_loss_rate * self.rtt_ms()
    }

    /// Calculate total network delay for a protocol phase
    fn calculate_delay(&self, round_count: u32, total_bytes: u64, message_count: u32) -> f64 {
        let latency_delay = (round_count as f64) * self.rtt_ms();
        let bandwidth_delay = self.transmission_delay_ms(total_bytes);
        let loss_overhead = self.retransmission_overhead(message_count);
        
        latency_delay + bandwidth_delay + loss_overhead
    }
}

/// Calculate network cost for a configuration
fn calculate_network_cost(max_signers: u16, min_signers: u16) -> ProtocolCostSummary {
    let mut summary = ProtocolCostSummary::new();
    
    // DKG cost
    let mut dkg = DkgCost::new(max_signers, min_signers);
    dkg.calculate_round1();
    dkg.calculate_round2();
    dkg.calculate_round3();
    summary.dkg_cost = Some(dkg);
    
    // DVRF cost (min_signers participants)
    let mut dvrf = DvrfCost::new(min_signers);
    dvrf.calculate_evaluation();
    dvrf.calculate_verification();
    summary.dvrf_cost = Some(dvrf);
    
    // FROST TSS cost (min_signers participants)
    let mut tss = FrostTssCost::new(min_signers);
    tss.calculate_round1_commitments();
    tss.calculate_round2_signatures();
    tss.calculate_aggregation();
    summary.tss_cost = Some(tss);
    
    summary
}

/// Simulated WAN delay for protocol WITH DKG
fn wan_simulation_with_dkg(c: &mut Criterion) {
    let configs = vec![
        (5, 3), (9, 5), (13, 7), (19, 10),
        (29, 15), (39, 20), (59, 30), (99, 50)
    ];

    let wan_params = vec![WanParams::wan1(), WanParams::wan2()];

    println!("\n╔═══════════════════════════════════════════════════════════════╗");
    println!("║         WAN SIMULATION - WITH DKG (DKG + DVRF + FROST)       ║");
    println!("╚═══════════════════════════════════════════════════════════════╝\n");

    for wan in &wan_params {
        println!("\n{} Configuration:", wan.name);
        println!("  - One-way latency: {}ms ± {}ms", wan.one_way_latency_ms, wan.latency_jitter_ms);
        println!("  - RTT: {}ms", wan.rtt_ms());
        println!("  - Bandwidth: {} Mbps", wan.bandwidth_mbps);
        println!("  - Packet loss: {}%\n", wan.packet_loss_rate * 100.0);

        println!("{:<12} | {:<15} | {:<15} | {:<15} | {:<15}", 
            "Config", "DKG Delay (ms)", "DVRF Delay (ms)", "TSS Delay (ms)", "Total (ms)");
        println!("{:-<12}-+-{:-<15}-+-{:-<15}-+-{:-<15}-+-{:-<15}", "", "", "", "", "");

        for (max, min) in &configs {
            let summary = calculate_network_cost(*max, *min);
            
            let dkg_delay = if let Some(dkg) = &summary.dkg_cost {
                let cost = dkg.total_cost();
                wan.calculate_delay(cost.round_count, cost.total_bytes(), cost.message_count)
            } else {
                0.0
            };

            let dvrf_delay = if let Some(dvrf) = &summary.dvrf_cost {
                let cost = dvrf.total_cost();
                wan.calculate_delay(cost.round_count, cost.total_bytes(), cost.message_count)
            } else {
                0.0
            };

            let tss_delay = if let Some(tss) = &summary.tss_cost {
                let cost = tss.total_cost();
                wan.calculate_delay(cost.round_count, cost.total_bytes(), cost.message_count)
            } else {
                0.0
            };

            let total_delay = dkg_delay + dvrf_delay + tss_delay;

            println!("{:<12} | {:<15.2} | {:<15.2} | {:<15.2} | {:<15.2}", 
                format!("{}/{}", max, min), dkg_delay, dvrf_delay, tss_delay, total_delay);
        }
        println!("\n");
    }

    // Dummy benchmark to satisfy criterion
    let mut group = c.benchmark_group("WAN_withDKG");
    for wan in &wan_params {
        for (max, min) in &configs {
            group.bench_with_input(
                BenchmarkId::new(wan.name, format!("{}/{}", max, min)),
                &(*max, *min),
                |b, &(max_signers, min_signers)| {
                    b.iter(|| {
                        let summary = calculate_network_cost(max_signers, min_signers);
                        let total = summary.total_cost();
                        wan.calculate_delay(total.round_count, total.total_bytes(), total.message_count)
                    });
                },
            );
        }
    }
    group.finish();
}

/// Simulated WAN delay for protocol WITHOUT DKG
fn wan_simulation_without_dkg(c: &mut Criterion) {
    let configs = vec![
        (5, 3), (9, 5), (13, 7), (19, 10),
        (29, 15), (39, 20), (59, 30), (99, 50)
    ];

    let wan_params = vec![WanParams::wan1(), WanParams::wan2()];

    println!("\n╔═══════════════════════════════════════════════════════════════╗");
    println!("║       WAN SIMULATION - WITHOUT DKG (DVRF + FROST only)       ║");
    println!("╚═══════════════════════════════════════════════════════════════╝\n");

    for wan in &wan_params {
        println!("\n{} Configuration:", wan.name);
        println!("  - One-way latency: {}ms ± {}ms", wan.one_way_latency_ms, wan.latency_jitter_ms);
        println!("  - RTT: {}ms", wan.rtt_ms());
        println!("  - Bandwidth: {} Mbps", wan.bandwidth_mbps);
        println!("  - Packet loss: {}%\n", wan.packet_loss_rate * 100.0);

        println!("{:<12} | {:<15} | {:<15} | {:<15}", 
            "Config", "DVRF Delay (ms)", "TSS Delay (ms)", "Total (ms)");
        println!("{:-<12}-+-{:-<15}-+-{:-<15}-+-{:-<15}", "", "", "", "");

        for (max, min) in &configs {
            let summary = calculate_network_cost(*max, *min);
            
            // WITHOUT DKG: only DVRF + FROST
            let dvrf_delay = if let Some(dvrf) = &summary.dvrf_cost {
                let cost = dvrf.total_cost();
                wan.calculate_delay(cost.round_count, cost.total_bytes(), cost.message_count)
            } else {
                0.0
            };

            let tss_delay = if let Some(tss) = &summary.tss_cost {
                let cost = tss.total_cost();
                wan.calculate_delay(cost.round_count, cost.total_bytes(), cost.message_count)
            } else {
                0.0
            };

            let total_delay = dvrf_delay + tss_delay;

            println!("{:<12} | {:<15.2} | {:<15.2} | {:<15.2}", 
                format!("{}/{}", max, min), dvrf_delay, tss_delay, total_delay);
        }
        println!("\n");
    }

    // Dummy benchmark to satisfy criterion
    let mut group = c.benchmark_group("WAN_withoutDKG");
    for wan in &wan_params {
        for (max, min) in &configs {
            group.bench_with_input(
                BenchmarkId::new(wan.name, format!("{}/{}", max, min)),
                &(*max, *min),
                |b, &(max_signers, min_signers)| {
                    b.iter(|| {
                        let summary = calculate_network_cost(max_signers, min_signers);
                        
                        let dvrf_delay = if let Some(dvrf) = &summary.dvrf_cost {
                            let cost = dvrf.total_cost();
                            wan.calculate_delay(cost.round_count, cost.total_bytes(), cost.message_count)
                        } else {
                            0.0
                        };

                        let tss_delay = if let Some(tss) = &summary.tss_cost {
                            let cost = tss.total_cost();
                            wan.calculate_delay(cost.round_count, cost.total_bytes(), cost.message_count)
                        } else {
                            0.0
                        };

                        dvrf_delay + tss_delay
                    });
                },
            );
        }
    }
    group.finish();
}

criterion_group!(
    benches,
    wan_simulation_with_dkg,
    wan_simulation_without_dkg
);

criterion_main!(benches);
