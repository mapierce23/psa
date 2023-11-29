use zkp::CompactProof;
use zkp::ProofError;
use zkp::Transcript;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::RistrettoPoint;
use crate::dpf::*;
use crate::Group;
use crate::u32_to_bits;

lazy_static! {
    pub static ref GEN_G: RistrettoPoint =
        RistrettoPoint::hash_from_bytes::<Sha512>(b"CMZ Generator A");
    pub static ref GEN_H: RistrettoPoint = dalek_constants::RISTRETTO_BASEPOINT_POINT;
}
// =======================================================================
// 								   PROOFS
// =======================================================================
define_proof! {
  transaction,                             // Name of the module
  "Transaction Proof",                     // Label for the proof statement
  (a, b, r_a, r_b, r_lam),                 // Secret variables
  (C_a, C_b, C_lam, C_ra, C_rb, C_rlam),   // Pub variables unique to each proof
  (G, H) :                                 // Pub variables common between proofs
  C_b = (G * b + H * r_b),                 // Statements to prove
  C_a = (G * a + H * r_a),
  C_lam = (G * (a * b) + H * r_lam),
  C_ra = G * r_a,
  C_rb = G * r_b, 
  C_rlam = G * r_lam,
}
// ========================================================================

// INPUT: a DPF key representing index ALPHA and value BETA
// INPUT: client-provided randomness for commitments
// Computes commitments to shares of BETA and LAMBDA = ALPHA * BETA using provided randomness
// OUTPUT: C_beta, C_lambda
pub fn compute_coms_from_dpf(
	dpf_key: SketchDPFKey<FieldElm, FieldElm>, 
	r_beta: u64,
	r_lambda: u64,
) -> (RistrettoPoint, RistrettoPoint) {

	// First we are going to EVAL on the entire domain
	let vec_eval = eval_all(dpf_key, MAX_GROUP_SIZE * MAX_GROUP_NUM);

	// Create commitment to value BETA
	let mut beta_b = FieldElm::zero();
	for i in 0..MAX_GROUP_NUM * MAX_GROUP_SIZE {
		beta_b.add(&vec_eval[i]);
	}
	let com_beta = create_com(beta_b, r_beta);

	// Create commitment to LAMBDA = ALPHA * BETA
	alpha_b = FieldElm::zero();
	for i in 0..MAX_GROUP_NUM * MAX_GROUP_SIZE {
		let mut sum = FieldElm::zero();
		sum.add(&vec_eval[i]);
		sum.mul(&FieldElm::from(i + 1));
		alpha_b.add(sum);
	}
	let com_lam = create_com(alpha_b, r_lambda);

	return (com_beta, com_lam);
}
// Verify the commitments computed from the DPFs. This function is only 
// used by S1. If this verifies, we know that the commitments to ALPHA
// and BETA are valid.
pub fn verify_coms_from_dpf(
	g_rbeta: RistrettoPoint,
	g_rlambda: RistrettoPoint,
	g_ra: RistrettoPoint,
	com_a: RistrettoPoint,
	com_b: RistrettoPoint,
	com_l: RistrettoPoint,
	transact_pf: CompactProof,
) -> Result<(RistrettoPoint, RistrettoPoint), ProofError> {

	let G: &RistrettoPoint = &GEN_G;
	let H: &RistrettoPoint = &GEN_H;
	// VERIFY PROOF
	let mut transcript = Transcript::new(b"Transaction Proof");
    transaction::verify_compact(
        &transact_pf,
        &mut transcript,
        issue::VerifyAssignments {
            G: &G.compress(),
            H: &H.compress(),
            C_a: &com_a.compress(),
            C_b: &com_b.compress(),
            C_lam: &com_l.compress(),
            C_ra: &g_ra.compress(),
            C_rb: &g_rbeta.compress(),
            C_rlam: &g_rlambda.compress(),
        },
    )?;
    Ok((com_a, com_b));
}