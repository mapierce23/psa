use curve25519_dalek::constants;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use ring::{hmac, rand};

use cmz::ggm::*;


#[derive(Debug)]
pub struct GroupToken {
	uid: u64,
	cm_aid: u64, 
	mac_tag: hmac::Tag, 
	cm_secret: u64,
}

impl GroupToken {

	pub fn new(uid_new: u64, cm_aid_new: u64, mac_tag_new: hmac::Tag, cm_secret_new: u64) -> GroupToken {
		uid = uid_new;
		cm_aid = cm_aid_new;
		mac_tag = mac_tag_new;
		cm_secret = cm_secret_new;
	}
}

#[derive(Debug)]
pub struct ServerData {
	db: Vec<u64>, 
	activityLog: Vec<[u64; 3]>, // encryptions of i, j,  & x under s
	prf_keys: Vec<u64>,
	group_tokens: Vec<GroupToken>,
	issuer: Issuer,

}

#[derive(Debug)]
pub struct GpMemberData {
	gt: GroupToken,
	s: u64,
	prf_keys: Vec<[u64; 2]>,
	aid: u64,
	uid: u64, 
}

pub struct GpLeaderData {
	self_mem: GpMemberData,
	gp_uids: Vec<u64>,
	gp_secret: u64,
	gp_size: u64,
	req_states: Vec<CredentialRequestState>,
}

impl ServerData {

	pub fn setup_new_group(prf_key: u64) -> Vec<u64> {

		// 1) Allocates M indices for the group by adding M zeros
		// to the vector database. The new AIDs for the group are 
		// (newLength, newLength - M)
		let aids = Vec::new();
		for i in 0..M {
			aids.push(db.len());
			db.push(0);
		}

		// 2) Store the prf key in the prf_keys vector at this group index. 
		prf_keys.push(prf_key);

		// Return set of M indices to user
		return aids;
	}

	pub fn setup_reg_tokens(reqs: Vec<CredentialRequest>) -> Vec<CredentialResponse> {

		issuer = Issuer::new(5);
		reg_tokens = Vec<CredentialResponse>::new();
		for req in reqs {
			let resp = issuer.issue_blind124_5(req);
			reg_tokens.add(resp);
		}
		return reg_tokens;
	}

	pub fn register_user(reg_token: ShowMessage) -> GroupToken {
		let result = issuer.verify_blind345_5(reg_token);
		let ver_cred = result.unwrap();

		// Server produces a MAC tag on UID (ver_cred.m1) and commitment to AID (ver_cred.m3)
		let rng = rand::SystemRandom::new();
		let key = hmac::Key::generate(hmac::HMAC_SHA256, &rng)?;
		let mac_tag = hmac::sign(&key, (ver_cred.m1 + ver_credm.m3).to_ne_bytes());

		let group_token = GroupToken::new(ver_cred.m1, ver_cred.m3, mac_tag, ver_cred.m5);
		return group_token;
	}

	pub fn transact(dpf_key_src: u64, dpf_key_dest: u64, gt: GroupToken, act_log: LogEntry) -> bool {
		// check group token 
		// verify i
		// verify j
		// verify LogEntry, add to activity log
		// perform actual transaction
	}

	pub fn settle() {

	}
}

impl GpLeaderData {

	pub fn group_creation_request() -> u64 {
		// Group leader requests creation of a new group
	}

	// Create credential requests for (UID, AID, s) tuples
	pub fn group_setup(aids: Vec<u64>) -> Vec<CredentialRequest> {

		let i = 0;
		let reqs = Vec<CredentialRequest>::new();

		// Not using these, so they can just be one
		let m2 = Scalar::one();
		let m4 = Scalar::one();

		for aid in aids {

			let m1 = Scalar::from((gp_uids[i])u64);
			let m3 = Scalar::from((aid)u64);
			let m5 = Scalar::from((gp_secret)u64);

			let (req, state) = issue_blind124_5::request(&m1, &m2, &m3, &m4, &m5);
			reqs.push(req);
			req_states.push(state);

			i = (i + 1) % gp_size;
		}
		return reqs;
	}

	// Verify credentials issued by Server
	pub fn group_setup_verify(resps: Vec<CredentialResponse>) -> Vec<Credential> {

		let i = 0;
		let creds = Vec<Credential>::new();
		for resp in resps {
			let result = issue_blind124_5::verify(req_states[i], resp.unwrap(), &issuer.publickey);
			if result.is_ok() {
				creds.push(result.unwrap());
			}
		}
	}

	// Function to send credential (Reg Token) to other members?	
}

impl GpMemberData {

	pub fn register_with_server(cred: Credential) -> ShowMessage {
		let showmsg = show_blind345_5::show(&cred, &issuer.pubkey);
		return showmsg;
	}
}



