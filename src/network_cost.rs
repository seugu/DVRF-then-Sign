use std::collections::{BTreeMap, HashMap};
use serde::{Deserialize, Serialize};


#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct NetworkCost {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub message_count: u32,
    pub round_count: u32,
}

impl NetworkCost {
    pub fn new() -> Self {
        Self {
            bytes_sent: 0,
            bytes_received: 0,
            message_count: 0,
            round_count: 0,
        }
    }

    pub fn total_bytes(&self) -> u64 {
        self.bytes_sent + self.bytes_received
    }

    pub fn add(&mut self, other: &NetworkCost) {
        self.bytes_sent += other.bytes_sent;
        self.bytes_received += other.bytes_received;
        self.message_count += other.message_count;
        self.round_count = self.round_count.max(other.round_count);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DkgCost {
    pub max_signers: u16,
    pub min_signers: u16,
    
    pub round1_cost: NetworkCost,
    pub round2_cost: NetworkCost,
    pub round3_cost: NetworkCost,
    
    pub per_participant_cost: BTreeMap<u16, NetworkCost>,
}

impl DkgCost {
    pub fn new(max_signers: u16, min_signers: u16) -> Self {
        Self {
            max_signers,
            min_signers,
            round1_cost: NetworkCost::new(),
            round2_cost: NetworkCost::new(),
            round3_cost: NetworkCost::new(),
            per_participant_cost: BTreeMap::new(),
        }
    }

    pub fn calculate_round1(&mut self) {
        let n = self.max_signers as u64;
        let t = self.min_signers as u64;
        
        let commitment_size: u64 = 33;
        let commitments_per_participant = t; 
        
        let bytes_per_participant = commitment_size * commitments_per_participant;
        
        for i in 1..=self.max_signers {
            let mut cost = NetworkCost::new();
            cost.bytes_sent = bytes_per_participant * (n - 1);
            cost.bytes_received = bytes_per_participant * (n - 1);
            cost.message_count = ((n - 1) * 2) as u32; // send + receive
            cost.round_count = 1;
            
            self.per_participant_cost.insert(i, cost);
            self.round1_cost.add(&cost);
        }
        
        self.round1_cost.bytes_sent /= n;
        self.round1_cost.bytes_received /= n;
    }


    pub fn calculate_round2(&mut self) {
        let n = self.max_signers as u64;
        
        let encrypted_share_size: u64 = 80;
        
        for i in 1..=self.max_signers {
            let cost = self.per_participant_cost.get_mut(&i).unwrap();
            
            cost.bytes_sent += encrypted_share_size * (n - 1);
            cost.bytes_received += encrypted_share_size * (n - 1);
            cost.message_count += ((n - 1) * 2) as u32;
            
            let round2_addition = NetworkCost {
                bytes_sent: encrypted_share_size * (n - 1),
                bytes_received: encrypted_share_size * (n - 1),
                message_count: ((n - 1) * 2) as u32,
                round_count: 1,
            };
            self.round2_cost.add(&round2_addition);
        }
        
        self.round2_cost.bytes_sent /= n;
        self.round2_cost.bytes_received /= n;
    }


    pub fn calculate_round3(&mut self) {
        let n = self.max_signers as u64;
        
        let verification_response_size: u64 = 64;
        
        for i in 1..=self.max_signers {
            let cost = self.per_participant_cost.get_mut(&i).unwrap();
            
            cost.bytes_sent += verification_response_size * (n - 1);
            cost.bytes_received += verification_response_size * (n - 1);
            cost.message_count += ((n - 1) * 2) as u32;
            
            let round3_addition = NetworkCost {
                bytes_sent: verification_response_size * (n - 1),
                bytes_received: verification_response_size * (n - 1),
                message_count: ((n - 1) * 2) as u32,
                round_count: 1,
            };
            self.round3_cost.add(&round3_addition);
        }
        
        self.round3_cost.bytes_sent /= n;
        self.round3_cost.bytes_received /= n;
        self.round3_cost.round_count = 1;
    }

    pub fn total_cost(&self) -> NetworkCost {
        let mut total = NetworkCost::new();
        total.add(&self.round1_cost);
        total.add(&self.round2_cost);
        total.add(&self.round3_cost);
        total.round_count = 3; // DKG 3 round
        total
    }
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DvrfCost {
    pub signer_count: u16,
    pub per_signer_cost: BTreeMap<u16, NetworkCost>,
    pub broadcast_cost: NetworkCost,
    pub verification_cost: NetworkCost,
}

impl DvrfCost {
    pub fn new(signer_count: u16) -> Self {
        Self {
            signer_count,
            per_signer_cost: BTreeMap::new(),
            broadcast_cost: NetworkCost::new(),
            verification_cost: NetworkCost::new(),
        }
    }

    pub fn calculate_evaluation(&mut self) {
        let n = self.signer_count as u64;
        
        let partial_eval_size: u64 = 33 + 96;
        
        for i in 1..=self.signer_count {
            let mut cost = NetworkCost::new();
            
            cost.bytes_sent = partial_eval_size;
            cost.bytes_received = partial_eval_size * (n - 1);
            cost.message_count = n as u32; 
            cost.round_count = 1;
            
            self.per_signer_cost.insert(i, cost.clone());
            self.broadcast_cost.add(&cost);
        }
        
        self.broadcast_cost.bytes_sent /= n;
        self.broadcast_cost.bytes_received /= n;
    }

    pub fn calculate_verification(&mut self) {
        let n = self.signer_count as u64;
        
        self.verification_cost.message_count = (n * (n - 1)) as u32;
        self.verification_cost.round_count = 0; // Same round as evaluation
    }

    pub fn total_cost(&self) -> NetworkCost {
        let mut total = self.broadcast_cost.clone();
        total.round_count = 1; 
        total
    }
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrostTssCost {
    pub signer_count: u16,
    
    pub round1_commitment_cost: NetworkCost,
    pub round2_signature_cost: NetworkCost,
    pub aggregation_cost: NetworkCost,
    
    pub per_signer_cost: BTreeMap<u16, NetworkCost>,
}

impl FrostTssCost {
    pub fn new(signer_count: u16) -> Self {
        Self {
            signer_count,
            round1_commitment_cost: NetworkCost::new(),
            round2_signature_cost: NetworkCost::new(),
            aggregation_cost: NetworkCost::new(),
            per_signer_cost: BTreeMap::new(),
        }
    }

    pub fn calculate_round1_commitments(&mut self) {
        let n = self.signer_count as u64;
        
        let commitment_size: u64 = 66;
        
        for i in 1..=self.signer_count {
            let mut cost = NetworkCost::new();
            
            cost.bytes_sent = commitment_size;
            cost.bytes_received = commitment_size * (n - 1);
            cost.message_count = n as u32;
            cost.round_count = 1;
            
            self.per_signer_cost.insert(i, cost.clone());
            self.round1_commitment_cost.add(&cost);
        }
        
        self.round1_commitment_cost.bytes_sent /= n;
        self.round1_commitment_cost.bytes_received /= n;
    }

    pub fn calculate_round2_signatures(&mut self) {
        let n = self.signer_count as u64;
        
        let partial_sig_size: u64 = 32;
        
        for i in 1..=self.signer_count {
            let cost = self.per_signer_cost.get_mut(&i).unwrap();
            
            cost.bytes_sent += partial_sig_size;
            cost.bytes_received += partial_sig_size * (n - 1);
            cost.message_count += n as u32;
            
            let round2_addition = NetworkCost {
                bytes_sent: partial_sig_size,
                bytes_received: partial_sig_size * (n - 1),
                message_count: n as u32,
                round_count: 1,
            };
            self.round2_signature_cost.add(&round2_addition);
        }
        
        self.round2_signature_cost.bytes_sent /= n;
        self.round2_signature_cost.bytes_received /= n;
    }

    pub fn calculate_aggregation(&mut self) {
        let final_sig_size: u64 = 64;
        
        self.aggregation_cost.bytes_sent = final_sig_size;
        self.aggregation_cost.message_count = self.signer_count as u32;
        self.aggregation_cost.round_count = 0; 
    }

    pub fn total_cost(&self) -> NetworkCost {
        let mut total = NetworkCost::new();
        total.add(&self.round1_commitment_cost);
        total.add(&self.round2_signature_cost);
        total.add(&self.aggregation_cost);
        total.round_count = 2; // FROST 2 round
        total
    }
}



#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolCostSummary {
    pub dkg_cost: Option<DkgCost>,
    pub dvrf_cost: Option<DvrfCost>,
    pub tss_cost: Option<FrostTssCost>,
}

impl ProtocolCostSummary {
    pub fn new() -> Self {
        Self {
            dkg_cost: None,
            dvrf_cost: None,
            tss_cost: None,
        }
    }

    pub fn total_cost(&self) -> NetworkCost {
        let mut total = NetworkCost::new();
        
        if let Some(dkg) = &self.dkg_cost {
            total.add(&dkg.total_cost());
        }
        if let Some(dvrf) = &self.dvrf_cost {
            total.add(&dvrf.total_cost());
        }
        if let Some(tss) = &self.tss_cost {
            total.add(&tss.total_cost());
        }
        
        total
    }

    pub fn generate_report(&self) -> String {
        let mut report = String::from("=== NETWORK COST RAPORU ===\n\n");
        
        if let Some(dkg) = &self.dkg_cost {
            let cost = dkg.total_cost();
            report.push_str(&format!(
                "DKG ({}/{} threshold):\n",
                dkg.min_signers, dkg.max_signers
            ));
            report.push_str(&format!("  - Toplam Bytes: {} ({:.2} KB)\n", 
                cost.total_bytes(), cost.total_bytes() as f64 / 1024.0));
            report.push_str(&format!("  - Mesaj Sayısı: {}\n", cost.message_count));
            report.push_str(&format!("  - Round Sayısı: {}\n", cost.round_count));
            report.push_str(&format!("  - Round 1: {:.2} KB\n", 
                dkg.round1_cost.total_bytes() as f64 / 1024.0));
            report.push_str(&format!("  - Round 2: {:.2} KB\n", 
                dkg.round2_cost.total_bytes() as f64 / 1024.0));
            report.push_str(&format!("  - Round 3: {:.2} KB\n\n", 
                dkg.round3_cost.total_bytes() as f64 / 1024.0));
        }
        
        if let Some(dvrf) = &self.dvrf_cost {
            let cost = dvrf.total_cost();
            report.push_str(&format!(
                "DVRF ({} signers):\n",
                dvrf.signer_count
            ));
            report.push_str(&format!("  - Toplam Bytes: {} ({:.2} KB)\n", 
                cost.total_bytes(), cost.total_bytes() as f64 / 1024.0));
            report.push_str(&format!("  - Mesaj Sayısı: {}\n", cost.message_count));
            report.push_str(&format!("  - Round Sayısı: {}\n\n", cost.round_count));
        }
        
        if let Some(tss) = &self.tss_cost {
            let cost = tss.total_cost();
            report.push_str(&format!(
                "FROST TSS ({} signers):\n",
                tss.signer_count
            ));
            report.push_str(&format!("  - Toplam Bytes: {} ({:.2} KB)\n", 
                cost.total_bytes(), cost.total_bytes() as f64 / 1024.0));
            report.push_str(&format!("  - Mesaj Sayısı: {}\n", cost.message_count));
            report.push_str(&format!("  - Round Sayısı: {}\n\n", cost.round_count));
        }
        
        let total = self.total_cost();
        report.push_str("=== GENEL TOPLAM ===\n");
        report.push_str(&format!("Toplam Bandwidth: {} bytes ({:.2} KB)\n", 
            total.total_bytes(), total.total_bytes() as f64 / 1024.0));
        report.push_str(&format!("Toplam Mesaj: {}\n", total.message_count));
        report.push_str(&format!("Toplam Round: {}\n", total.round_count));
        
        report
    }
}



#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_full_protocol_cost() {
        let mut summary = ProtocolCostSummary::new();
        
        // DKG: 5-out-of-4 threshold
        let mut dkg = DkgCost::new(5, 4);
        dkg.calculate_round1();
        dkg.calculate_round2();
        dkg.calculate_round3();
        summary.dkg_cost = Some(dkg);
        
        // DVRF: 4 signer
        let mut dvrf = DvrfCost::new(4);
        dvrf.calculate_evaluation();
        dvrf.calculate_verification();
        summary.dvrf_cost = Some(dvrf);
        
        // FROST TSS: 4 signer
        let mut tss = FrostTssCost::new(4);
        tss.calculate_round1_commitments();
        tss.calculate_round2_signatures();
        tss.calculate_aggregation();
        summary.tss_cost = Some(tss);
        
        // Rapor yazdır
        println!("{}", summary.generate_report());
        
        // Assertions
        let total = summary.total_cost();
        assert!(total.total_bytes() > 0);
        assert!(total.round_count > 0);
    }
}
