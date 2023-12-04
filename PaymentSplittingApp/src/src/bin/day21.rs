#![allow(non_snake_case)]
#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]
extern crate crypto;

use zkp::CompactProof;
use zkp::ProofError;
use zkp::Transcript;
use lazy_static::lazy_static;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::traits::IsIdentity;
use curve25519_dalek::traits::Identity;
use curve25519_dalek::constants as dalek_constants;
use sha2::Sha512;
use std::ops::Neg;
use std::time::{Duration, SystemTime};
use rand::Rng;
use payapp::coms::transaction;
use payapp::prg::PrgSeed;
use payapp::FieldElm;
use payapp::u32_to_bits;
use payapp::my_u32_to_bits;
use payapp::Group;
use payapp::mpc;
use payapp::Share;

use payapp::sketch::*;
use payapp::coms::*;
use payapp::prg;
use payapp::ps::*;
use payapp::dpf::*;
use payapp::ggm::*;

lazy_static! {
    pub static ref GEN_G: RistrettoPoint =
        RistrettoPoint::hash_from_bytes::<Sha512>(b"CMZ Generator A");
    pub static ref GEN_H: RistrettoPoint = dalek_constants::RISTRETTO_BASEPOINT_POINT;
}

fn mpc_test() {
    let nbits = 8;
    let alpha_s = my_u32_to_bits(nbits, 30);
    println!("");
    let betas = vec![
        FieldElm::from(0u32),
        FieldElm::from(0u32),
        FieldElm::from(0u32),
        FieldElm::from(0u32),
        FieldElm::from(0u32),
        FieldElm::from(0u32),
        FieldElm::from(4u32),
    ];
    let beta_last = FieldElm::from(0u32);
    let keys = SketchDPFKey::gen(&alpha_s, &betas, &beta_last);
    // let keys_d = SketchDPFKey::gen(&alpha_d, &betas, &beta_last);

    let level = nbits;
    let seed = PrgSeed::random();

    // Full Domain Evaluation
    let now = SystemTime::now();
    let vec1 = keys[0].key.eval_all();
    let vec2 = keys[1].key.eval_all(); 
    match now.elapsed() {
        Ok(elapsed) => {
            // it prints '2'
            println!("{}", elapsed.as_nanos());
        }
        Err(e) => {
            // an error occurred!
            println!("Error: {e:?}");
        }
    }

    let x = FieldElm::from(4u32);
    let (y1, y2) = x.share();

    let mut sketches = vec![];
    sketches.push(keys[0].sketch_at(&vec1, &mut seed.to_rng()));
    sketches.push(keys[1].sketch_at(&vec2, &mut seed.to_rng()));

    let state0 = mpc::MulState::new(false, keys[0].triples.clone(), &keys[0].mac_key, &keys[0].mac_key2, &y1.clone(), &sketches[0]);
    let state1 = mpc::MulState::new(true, keys[1].triples.clone(), &keys[1].mac_key, &keys[1].mac_key2, &y2.clone(), &sketches[1]);

    let corshare0 = state0.cor_share();
    let corshare1 = state1.cor_share();

    let cor = mpc::MulState::cor(&corshare0, &corshare1);

    let outshare0 = state0.out_share(&cor);
    let outshare1 = state1.out_share(&cor);

    assert!(mpc::MulState::verify(&outshare0, &outshare1));
}
fn main() {
    mpc_test();
}
