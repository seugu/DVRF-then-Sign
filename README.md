This repo contains DVRF and Treshold signature framework for: Provably Secure and Collusion-Resistant TLS Attestation Protocols for Decentralized Applications

We have 3 benchmarks that run the DVRF-then-TSS part for t-out-of-n nodes, (5, 3), (9, 5), (13, 7), (19, 10), (29, 15), (39, 20), (59, 30), (99, 50).

- Generation time **with** Distributed Key Generation

```
cargo bench --bench ddh-dvrf_frost_bench_withDKG 
``` 
runs  each t-out-of-n nodes attestation JF DKG > DDH-DVRF > FROST TSS

- Generation time **without** Distributed Key Generation

```
cargo bench --bench ddh-dvrf_frost_bench_withoutDKG 
``` 
runs  each t-out-of-n nodes attestation DDH-DVRF > FROST TSS

- Calculates network cost

```
cargo bench --bench network_cost_bench.rs
``` 

Warning!: This code is a research prototype. Do not use it in production.
