## This repo is moved to https://github.com/CanDenizGokgedik/collusion-resistant-zktls-gnark 


This repo contains DVRF and Treshold signature framework for: Provably Secure and Collusion-Resistant TLS Attestation Protocols for Decentralized Applications

We have 4 benchmarks that run the DVRF-then-TSS part for t-out-of-n nodes, (5, 3), (9, 5), (13, 7), (19, 10), (29, 15), (39, 20), (59, 30), (99, 50) including LAN and WAN (simulated).

- LAN Generation time **with** Distributed Key Generation 

```
cargo bench --bench ddh-dvrf_frost_bench_withDKG 
``` 
runs  each t-out-of-n nodes attestation JF DKG > DDH-DVRF > FROST TSS

- LAN Generation time **without** Distributed Key Generation

```
cargo bench --bench ddh-dvrf_frost_bench_withoutDKG 
``` 
runs  each t-out-of-n nodes attestation DDH-DVRF > FROST TSS

- Calculates network cost

```
cargo bench --bench network_cost_bench.rs
``` 

- WAN simulation generation time with two different WAN features

WAN1 Configuration:
  - One-way latency: 40ms ± 5ms
  - RTT: 80ms
  - Bandwidth: 50 Mbps
  - Packet loss: 0.1%


WAN2 Configuration:
  - One-way latency: 75ms ± 15ms
  - RTT: 150ms
  - Bandwidth: 20 Mbps
  - Packet loss: 0.2%


```
cargo bench --bench wan_simulation_bench.rs
``` 

Warning!: This code is a research prototype. Do not use it in production.
