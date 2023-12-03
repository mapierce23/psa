#![allow(non_snake_case)]

extern crate crypto; 

use crypto::aes::{self, KeySize};
use crypto::symmetriccipher::SynchronousStreamCipher;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::constants as dalek_constants;
use curve25519_dalek::ristretto::CompressedRistretto;
use ring::error::Unspecified;
use serde::Deserialize;
use serde::Serialize;
use std::net::TcpStream;
use std::io::{Read,Write};
use std::convert::TryInto; 
use sha2::Sha256;
use hmac::{Hmac, Mac};
use std::iter::repeat;
use zkp::CompactProof;
use sha2::Sha512;
use rand::Rng;
use crate::sketch::SketchDPFKey;

use crate::ggm::*;
use crate::dpf::*;
use crate::sketch::*;
use crate::mpc::*;
use crate::Group;
use crate::u32_to_bits;
use crate::FieldElm;
use crate::MAX_GROUP_SIZE;
use crate::MAX_GROUP_NUM;
use crate::DPF_DOMAIN;


// Write pseudocode or definitions after this
// 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
// sign up for 992
// LEFT TO DO: CODE
// - Transaction ID protocol

lazy_static! {
    pub static ref GEN_G: RistrettoPoint =
        RistrettoPoint::hash_from_bytes::<Sha512>(b"CMZ Generator A");
    pub static ref GEN_H: RistrettoPoint = dalek_constants::RISTRETTO_BASEPOINT_POINT;
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GroupToken {
	pub P: CompressedRistretto,
	pub uid: Scalar,
	pub cm_aid: CompressedRistretto,
	pub mac_tag: Vec<u8>, 
}
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GroupTokenPriv {
	pub prf_keys: (Vec<u8>, Vec<u8>),
	pub token: GroupToken,
	pub z3: Scalar,
	pub aid: Scalar,
}

impl GroupToken {

	pub fn new(P: CompressedRistretto, uid: Scalar, cm_aid: CompressedRistretto, mac_tag: Vec<u8>) -> GroupToken {
		GroupToken { P, uid, cm_aid, mac_tag }
	}
}

#[derive(Clone, Debug)]
pub struct ServerData {
	issuer: Issuer,
}

pub struct GpLeaderData {
	gp_uids: Vec<Scalar>,
	gp_size: usize,
}

#[derive(Serialize, Deserialize)]
pub struct TransactionData { 
	pub tokens: Vec<GroupToken>,
	pub id: u8,
	pub dpf_src: SketchDPFKey<FieldElm, FieldElm>,
	pub dpf_dest: SketchDPFKey<FieldElm, FieldElm>,
	pub g_r1: CompressedRistretto, // r1 is the randomness used to create com_a
	pub r2: Scalar,           // Share of randomness to calculate commitment to x
	pub r3: Scalar,           // Share of randomness to calculate commitment to i * x
	pub com_i: CompressedRistretto, 
	pub triple_proof: CompactProof,
	pub token_proof: CompactProof,
}

#[derive(Serialize, Deserialize)]
pub struct SettleData {
	pub dpf_key: DPFKey<FieldElm, FieldElm>,
	pub r_seed: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct TransactionPackage<'a> {
	pub strin: &'a str,
    pub gp_val_ver: Vec<u8>,
    pub com_x: CompressedRistretto,
    pub com_ix: CompressedRistretto,
    pub g_r2: CompressedRistretto,
    pub g_r3: CompressedRistretto,
    pub cshare_s: CorShare<FieldElm>,
    pub cshare_d: CorShare<FieldElm>,
}

impl ServerData {

	pub fn new(issuer: Issuer) -> ServerData {
		return ServerData {issuer};
	}

	pub fn setup_new_group(&mut self, start: &usize) -> (Vec<usize>, IssuerPubKey) {

		// 1) Allocates M indices for the group by adding M zeros
		// to the vector database. The new AIDs for the group are 
		// (newLength, newLength - M)
		let mut aids = Vec::new();
		for i in 0..MAX_GROUP_SIZE {
			aids.push(*start + i);
		}

		// Return set of M indices to user
		return (aids, (self.issuer.pubkey).clone());
	}

	pub fn setup_reg_tokens(&mut self, reqs: Vec<issue_blind124_5::CredentialRequest>) -> Vec<issue_blind124_5::CredentialResponse> {

		let mut reg_tokens = Vec::<issue_blind124_5::CredentialResponse>::new();
		for req in reqs {
			let resp = self.issuer.issue_blind124_5(req);
			reg_tokens.push(resp.unwrap());
		}
		return reg_tokens;
	}

	pub fn register_user(&mut self, reg_token: show_blind345_5::ShowMessage, mac: &Hmac<Sha256>) -> Result<GroupToken, Unspecified> {
		let result = self.issuer.verify_blind345_5(reg_token);
		let (P, ver_cred) = result.unwrap();

		// Server produces a MAC tag on UID (ver_cred.m1) and commitment to AID (ver_cred.m3)
		let mut my_mac = mac.clone();
		let mut macinput: Vec<u8> = Vec::new();
		macinput.extend_from_slice(&ver_cred.m1.to_bytes());
		macinput.extend_from_slice(&(ver_cred.Cm3).compress().to_bytes());
		let macinput_bytes: &[u8] = &macinput;
		my_mac.update(macinput_bytes);
		let result_bytes = (my_mac.finalize()).into_bytes();

		let group_token = GroupToken::new(P.compress(), ver_cred.m1, ver_cred.Cm3.compress(), result_bytes.to_vec());
		return Ok(group_token);
	}

	// Only to be called once all verifications have been completed. 
	// We're taking money from the source and giving it to the dest.
	pub fn transact(db: &mut Vec<FieldElm>, src_vec: &Vec<FieldElm>, dest_vec: &Vec<FieldElm>) {
		for i in 0..MAX_GROUP_SIZE * MAX_GROUP_NUM {
			db[i].add(&src_vec[i]);
			db[i].sub(&dest_vec[i]);
		}
	}
	pub fn encrypt_db(db: &Vec<FieldElm>, key: &Vec<Vec<u8>>, r_seed: Vec<u8>) -> (FieldElm, Vec<FieldElm>) {
    	let zero_bytes = [0u8; 16];
		// Disguise Database for Settling
		let mut enc_db = db.clone();
		let mut sum = FieldElm::zero();
		for j in 0..MAX_GROUP_NUM {
			// Reset the nonce for every group
			let mut prf = aes::ctr(KeySize::KeySize128, &key[j], &r_seed);
			for i in 0..MAX_GROUP_SIZE {
				let mut output: Vec<u8> = repeat(0u8).take(16).collect();
				prf.process(&zero_bytes, &mut output[..]);
				output.extend(zero_bytes.clone());
				let scalar = Scalar::from_bytes_mod_order(output.try_into().unwrap());
				enc_db[i + (j * MAX_GROUP_SIZE)].add(&FieldElm {value: scalar});
				sum.add(&enc_db[i + (j * MAX_GROUP_SIZE)]);
			}
		}
		return (sum, enc_db);
	}

	pub fn settle(enc_db1: &Vec<FieldElm>, enc_db2: &Vec<FieldElm>, keyb: &DPFKey<FieldElm, FieldElm>) -> Vec<FieldElm> {

		let mut enc_db = Vec::<FieldElm>::new();
		for i in 0..100 {
			let mut sum = FieldElm::zero();
			sum.add(&enc_db1[i]);
			sum.add(&enc_db2[i]);
			enc_db.push(sum);
		}
		let mut balance_vec = Vec::<FieldElm>::new();
		for i in 0..MAX_GROUP_SIZE {
			let mut total = FieldElm::zero();
			for j in 0..MAX_GROUP_NUM {
				let alpha_bits = u32_to_bits(6, j.try_into().unwrap());
				let mut evalb = keyb.eval(&alpha_bits[0..5].to_vec());
				evalb.0[3].mul(&(enc_db[(j * MAX_GROUP_SIZE) + i]));
				total.add(&evalb.0[3]);
			}
			balance_vec.push(total);
		}
		return balance_vec;
	}
}

impl GpLeaderData {

	pub fn new(gp_size: usize) -> GpLeaderData {
		let mut gp_uids = Vec::<Scalar>::new();
		let mut rng = rand::thread_rng();
		for i in 0..MAX_GROUP_SIZE {
			gp_uids.push(Scalar::random(&mut rng));
		}
		return GpLeaderData {gp_uids, gp_size};
	}

	// Create credential requests for (UID, AID, s) tuples
	pub fn group_setup(&mut self, aids: Vec<u64>, mut stream: &TcpStream, pk: IssuerPubKey) -> Result<Vec<Credential>, std::io::Error> {

		let mut i = 0;
		let mut reqs = Vec::<issue_blind124_5::CredentialRequest>::new();
		let mut req_states = Vec::<issue_blind124_5::CredentialRequestState>::new();

		// Not using these, so they can just be one
		let m2 = Scalar::one();
		let m4 = Scalar::one();
		let m5 = Scalar::one();

		for aid in aids {

			let m1 = self.gp_uids[i];
			let m3 = Scalar::from(aid);

			let (req, state) = issue_blind124_5::request(&m1, &m2, &m3, &m4, &m5);
			reqs.push(req);
			req_states.push(state);

			i = (i + 1) % self.gp_size;
		}
		let mut encoded: Vec<u8> = Vec::new();
		encoded.push(2u8);
		encoded.extend(bincode::serialize(&reqs).unwrap());
		println!("{:?}", encoded.len());
		let _ = stream.write(&encoded);
		let mut buf = [0;8196];
		let mut bytes_read = 0;
		while bytes_read == 0 {
			bytes_read = stream.read(&mut buf)?;
		}
		let resps: Vec<issue_blind124_5::CredentialResponse> = bincode::deserialize(&buf[0..bytes_read]).unwrap();
		
		// Once we get the Credential Responses:
		let mut i = 0;
		let mut creds = Vec::<Credential>::new();
		for resp in resps {
			let result = issue_blind124_5::verify(req_states[i], resp, &pk);
			if result.is_ok() {
				creds.push(result.unwrap());
			}
			else {
				println!("i is {:?}", i);
			}
			i += 1;
		}
		return Ok(creds);

	}
}	


impl GroupTokenPriv {

	pub fn decrypt_db(mut enc_db: Vec<FieldElm>, key1: Vec<u8>, key2: Vec<u8>, r_seed: Vec<u8>) -> Vec<FieldElm> {
		let zero_bytes = [0u8; 16];
    	let mut prf1 = aes::ctr(KeySize::KeySize128, &key1, &r_seed);
    	let mut prf2 = aes::ctr(KeySize::KeySize128, &key2, &r_seed);

		for i in 0..MAX_GROUP_SIZE {
			let mut output1: Vec<u8> = repeat(0u8).take(16).collect();
			let mut output2: Vec<u8> = repeat(0u8).take(16).collect();
			prf1.process(&zero_bytes, &mut output1[..]);
			prf2.process(&zero_bytes, &mut output2[..]);
			output1.extend(&zero_bytes);
			output2.extend(&zero_bytes);
			let scalar1 = Scalar::from_bytes_mod_order(output1.try_into().unwrap());
			let scalar2 = Scalar::from_bytes_mod_order(output2.try_into().unwrap());
			enc_db[i].sub(&FieldElm {value : scalar1});
			enc_db[i].sub(&FieldElm {value : scalar2});
		}
		return enc_db;
	}
}