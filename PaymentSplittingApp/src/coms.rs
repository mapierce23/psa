#![allow(non_snake_case)]
use zkp::CompactProof;
use zkp::ProofError;
use zkp::Transcript;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::ristretto::RistrettoBasepointTable;
use curve25519_dalek::constants as dalek_constants;
use curve25519_dalek::traits::Identity;
use sha2::Sha256;
use hmac::{Hmac, Mac, NewMac};
use crate::Group;
use crate::FieldElm;
use sha2::Sha512;
use crate::sketch::SketchDPFKey;
use std::convert::TryInto;
use std::ops::Neg;
use crate::ps::GroupToken;
use crate::MAX_GROUP_SIZE;
use crate::MAX_GROUP_NUM;

lazy_static! {
    pub static ref GEN_G: RistrettoPoint =
        RistrettoPoint::hash_from_bytes::<Sha512>(b"CMZ Generator A");
    pub static ref GEN_H: RistrettoPoint = dalek_constants::RISTRETTO_BASEPOINT_POINT;
    pub static ref GEN_G_TABLE: RistrettoBasepointTable = RistrettoBasepointTable::create(&GEN_G);
    pub static ref GEN_H_TABLE: RistrettoBasepointTable = dalek_constants::RISTRETTO_BASEPOINT_TABLE;
}

// =======================================================================
// 								   PROOFS
// =======================================================================
// Proof of an encrypted DH-triple
// Using notation/syntax from Boneh-Shoup Eq 20.4
// Here the prefix "n" denotes the inverse 
define_proof! {
  transaction,                             // Name of the module
  "Transaction Proof",                     // Label for the proof statement
  (r1, r3, a, id, tau),                    // Secret variables
  (v1, v2, v3, e1, e2, ne3),                // Pub variables unique to each proof
  (G, H, nG, nH) :                         // Pub variables common between proofs
  v1 = (r1*G),
  v3 = (r3*G),
  e1 = (a*G + r1*H),
  G = (a*v2 + tau*nG + id*G),
  ne3 = (id*ne3),
  G = (a*e2 + r3*H + tau*nH + id*ne3 + id*G)
}
define_proof! {
  token,                         // Name of the module
  "Group Token Proof",           // Label for the proof statement
  (i, rt, rc),                   // Secret variables
  (Ti, Ci),                      // Pub variables unique to each proof
  (G, H, P) :                     // Pub variables common between proofs
  Ti = (i*P + rt*G),
  Ci = (i*G + rc*H)
}
// ========================================================================

pub fn verify_group_tokens(proof: CompactProof, tokens: Vec<GroupToken>, ci: CompressedRistretto, mac: &Hmac<Sha256>) -> bool {

	let G: &RistrettoPoint = &GEN_G;
	let H: &RistrettoPoint = &GEN_H;
	let mut retval = false;
	let my_mac = mac.clone();
	// VERIFY PROOFS
	for i in 0..tokens.len() {
		let mut transcript = Transcript::new(b"Group Token Proof");
	    let ver = token::verify_compact(
	        &proof,
	        &mut transcript,
	        token::VerifyAssignments {
	            G: &G.compress(),
	            H: &H.compress(),
	            P: &tokens[i].P,
	            Ti: &tokens[i].cm_aid,
	            Ci: &ci,
	        },
	    );
	    if ver.is_ok() {
	    	retval = true;
	    }
	    let blah = my_mac.clone().verify(&tokens[i].mac_tag[..]);
	    if blah.is_ok() {
	    	println!("mac tag verified!");
	    }

	}
    return retval;
}
pub fn create_com(val: FieldElm, rand: Scalar) -> (RistrettoPoint, RistrettoPoint) {

    let Gtable: &RistrettoBasepointTable = &GEN_G_TABLE;
    let Htable: &RistrettoBasepointTable = &GEN_H_TABLE;
	// Compute commmitment = g^val * h^rand
	let com = &val.value * Gtable + &rand * Htable;
	let g_r = &rand * Gtable;
	return (com, g_r);
}
// INPUT: a DPF key representing index ALPHA and value BETA
// INPUT: client-provided randomness for commitments
// Computes commitments to shares of BETA and LAMBDA = ALPHA * BETA using provided randomness
// OUTPUT: C_beta, C_lambda
pub fn compute_coms_from_dpf(
	vec_eval: &Vec<FieldElm>,
	r_beta: Scalar,
	r_lambda: Scalar ,
) -> (CompressedRistretto, CompressedRistretto, CompressedRistretto, CompressedRistretto) {

	// Create commitment to value BETA
	let mut beta_b = FieldElm::zero();
	// Create commitment to LAMBDA = ALPHA * BETA
	let mut alpha_b = FieldElm::zero();
	for i in 0..MAX_GROUP_NUM * MAX_GROUP_SIZE {
		beta_b.add(&vec_eval[i]);
		let mut sum = FieldElm::zero();
		sum.add(&vec_eval[i]);
		let index: u32 = (i).try_into().unwrap();
		sum.mul(&FieldElm::from(index));
		alpha_b.add(&sum);
	}
	let (com_beta, g_rb) = create_com(beta_b, r_beta);
	let (com_lam, g_rl) = create_com(alpha_b, r_lambda);

	return (com_beta.compress(), com_lam.compress(), g_rb.compress(), g_rl.compress());
}

pub fn eval_all(keyb_s: &SketchDPFKey<FieldElm, FieldElm>, keyb_d: &SketchDPFKey<FieldElm, FieldElm>) -> (Vec<(FieldElm, FieldElm)>, Vec<(FieldElm, FieldElm)>, Vec<FieldElm>, Vec<FieldElm>) {
	let mut eval_vec_src = Vec::<FieldElm>::new();
	let mut eval_vec_dest = Vec::<FieldElm>::new();

	let eval_vec_s = keyb_s.key.eval_all();
    let eval_vec_d = keyb_d.key.eval_all(); 

	for i in 0..MAX_GROUP_SIZE * MAX_GROUP_NUM {
		let eval_elm_s: FieldElm = (eval_vec_s[i].0).clone();
		let eval_elm_d: FieldElm = (eval_vec_d[i].0).clone();
		eval_vec_src.push(eval_elm_s);
		eval_vec_dest.push(eval_elm_d);
	}
	return (eval_vec_s, eval_vec_d, eval_vec_src, eval_vec_dest);
}

// S1 & S2
// Should produce a share of the all-zero vector of length N, where N is the num of groups
pub fn same_group_val_compute(eval_all_src: &Vec<FieldElm>, eval_all_dest: &Vec<FieldElm>, server1: bool) -> Vec<FieldElm> {
	let mut result = Vec::<FieldElm>::new();
	for i in 0..MAX_GROUP_NUM {
		let mut sum_src = FieldElm::zero();
		let mut sum_dest = FieldElm::zero();
		let mut diff = FieldElm::zero();
		for j in 0..MAX_GROUP_SIZE {
			sum_src.add(&eval_all_src[j + i * MAX_GROUP_SIZE]);
			sum_dest.add(&eval_all_dest[j + i * MAX_GROUP_SIZE]);
		}
		diff.add(&sum_src);
		diff.sub(&sum_dest);
		if server1 {
			diff.negate();
		}
		result.push(diff);
	}
	return result;
}

// S1 ONLY
pub fn same_group_val_verify(result_1: &Vec<u8>, result_2: &Vec<u8>) -> bool {
	for i in 0..result_1.len() {
		let sum = result_1[i] - result_2[i];
		if sum != 0 {
			return false;
		}
	}
	return true;
}

// Verify the commitments computed from the DPFs. This function is only 
// used by S1. If this verifies, we know that the commitments to ALPHA
// and BETA are valid.
pub fn verify_coms_from_dpf(
	g_r1: RistrettoPoint,
	g_r2: RistrettoPoint,
	g_r3: RistrettoPoint,
	com_a: RistrettoPoint,
	com_b: RistrettoPoint,
	com_l: RistrettoPoint,
	transact_pf: CompactProof,
) -> Result<(RistrettoPoint, RistrettoPoint), ProofError> {

	let G: &RistrettoPoint = &GEN_G;
	let H: &RistrettoPoint = &GEN_H;
	let nG = G.clone().neg();
	let nH = H.clone().neg();
	let one = RistrettoPoint::identity();
	let ncom_l = com_l.clone().neg();
	// VERIFY PROOF
	let mut transcript = Transcript::new(b"Transaction Proof");
    transaction::verify_compact(
        &transact_pf,
        &mut transcript,
        transaction::VerifyAssignments {
            G: &G.compress(),
            H: &H.compress(),
            nG: &nG.compress(),
            nH: &nH.compress(),
            v1: &g_r1.compress(),
            e1: &com_a.compress(),
            v2: &g_r2.compress(),
            e2: &com_b.compress(),
            v3: &g_r3.compress(),
            ne3: &ncom_l.compress(),
        },
    )?;
    Ok((com_a, com_b))
}