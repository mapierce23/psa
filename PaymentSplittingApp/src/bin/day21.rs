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


fn try_it() -> Result<RistrettoPoint, ProofError> {

    let r1_bytes = rand::thread_rng().gen::<[u8; 32]>();
    let r2_bytes_1 = rand::thread_rng().gen::<[u8; 32]>();
    let r2_bytes_2 = rand::thread_rng().gen::<[u8; 32]>();
    let r3_bytes_1 = rand::thread_rng().gen::<[u8; 32]>();
    let r3_bytes_2 = rand::thread_rng().gen::<[u8; 32]>();

    let r1 = Scalar::hash_from_bytes::<Sha512>(&r1_bytes);
    let r2_1 = Scalar::hash_from_bytes::<Sha512>(&r2_bytes_1);
    let r2_2 = Scalar::hash_from_bytes::<Sha512>(&r2_bytes_2);
    let r2 = r2_1 + r2_2;
    let r3_1 = Scalar::hash_from_bytes::<Sha512>(&r3_bytes_1);
    let r3_2 = Scalar::hash_from_bytes::<Sha512>(&r3_bytes_2);
    let r3 = r3_1 + r3_2;

    let G: &RistrettoPoint = &GEN_G;
    let H: &RistrettoPoint = &GEN_H;
    let nG = G.clone().neg();
    let nH = H.clone().neg();
    let id = Scalar::one();
    let i_sc = Scalar::from(3u32);
    let x_sc = Scalar::from(5u32);
    let v1 = G * r1;
    let v2 = G * r2;
    let v3 = G * r3;
    let e1 = G * i_sc + H * r1;
    let e2 = G * x_sc + H * r2;
    let ix_sc = i_sc * x_sc;
    let e3 = G * ix_sc + H * r3;
    let tau = i_sc * r2;
    let ne3 = e3.clone().neg();

    let mut transcript = Transcript::new(b"Transaction Proof");
    // Create triple proof
    let transact_pf = transaction::prove_compact(
        &mut transcript,
        transaction::ProveAssignments {
            G: &G,
            H: &H,
            nG: &nG,
            nH: &nH,
            v1: &v1,
            v2: &v2,
            v3: &v3,
            e1: &e1,
            e2: &e2,
            ne3: &ne3,
            r1: &r1,
            r3: &r3,
            a: &i_sc,
            id: &id,
            tau: &tau,
        },
    )
    .0;
    let mut transcript = Transcript::new(b"Transaction Proof");
    transaction::verify_compact(
        &transact_pf,
        &mut transcript,
        transaction::VerifyAssignments {
            G: &G.compress(),
            H: &H.compress(),
            nG: &nG.compress(),
            nH: &nH.compress(),
            v1: &v1.compress(),
            v2: &v2.compress(),
            v3: &v3.compress(),
            e1: &e1.compress(),
            e2: &e2.compress(),
            ne3: &ne3.compress(),
        },
    )?;
    Ok(v1)
}

fn mpc_test() {
    let nbits = 8;
    let alpha_s = my_u32_to_bits(nbits, 30);
    for i in 0..alpha_s.len() {
        let mut a = 1;
        if alpha_s[i] == false { 
            a = 0;
        }
        print!("{:?}", a);
    }
    println!("");
    let betas = vec![
        FieldElm::from(10u32),
        FieldElm::from(20u32),
        FieldElm::from(30u32),
        FieldElm::from(40u32),
        FieldElm::from(50u32),
        FieldElm::from(60u32),
        FieldElm::from(70u32),
    ];
    let beta_last = FieldElm::from(0u32);
    let keys_s = SketchDPFKey::gen(&alpha_s, &betas, &beta_last);
    // let keys_d = SketchDPFKey::gen(&alpha_d, &betas, &beta_last);

    let level = nbits;
    let seed = PrgSeed::random();

    // Full Domain Evaluation
    let now = SystemTime::now();
    let eval_vec_0 = keys_s[0].key.eval_all();
    let eval_vec_1 = keys_s[1].key.eval_all(); 
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
    println!("Length:");
    println!("{:?}", eval_vec_0.len());
    for k in 0..eval_vec_0.len() {
        // let alpha_bits = u32_to_bits(nbits, k);
        // let eval1_s = keys_s[0].key.eval(&alpha_bits[0..8].to_vec());
        // let eval2_s = keys_s[1].key.eval(&alpha_bits[0..8].to_vec());
        // let eval1_d = keys_d[0].key.eval(&alpha_bits[0..8].to_vec());
        // let eval2_d = keys_d[1].key.eval(&alpha_bits[0..8].to_vec());
        // vec1_s.push((eval1_s.0[6].0).clone());
        // vec2_s.push((eval2_s.0[6].0).clone());
        // vec1_d.push((eval1_d.0[6].0).clone());
        // vec2_d.push((eval2_d.0[6].0).clone());
        let mut sum = FieldElm::zero();
        sum.add(&eval_vec_0[k].0);
        sum.add(&eval_vec_1[k].0);
        if sum.value != Scalar::from(0u32) {
            println!("{:?}", k);
            println!("{:?}", sum.value);
        }
    }
    // let issuer = Issuer::new(5);
    // let mut server_data = ServerData::new(issuer);
    // server_data.transact(&vec1_s, &vec1_d);
    // server_data.transact(&vec2_s, &vec2_d);

    // for i in 0..100 {
    //     if server_data.db[i] != FieldElm::zero() {
    //         println!("{:?}", -(server_data.db[i].value));
    //     }
    // }

    // let group_num: u32 = 21 / 10;

    // // DPF Key generation
    // let alpha_bits = u32_to_bits(5, group_num);
    // let values = vec![FieldElm::one(); alpha_bits.len() - 1];
    // let (key1, key2) = DPFKey::gen(&alpha_bits, &values, &FieldElm::one());

    // let b_vec1 = server_data.settle(&key1);
    // let b_vec2 = server_data.settle(&key2);

    // for i in 0..10 {
    //     let mut sum = FieldElm::zero();
    //     sum.add(&b_vec1[i]);
    //     sum.add(&b_vec2[i]);
    // }



    // let x = FieldElm::from(4u32);
    // let y = FieldElm::one();
    // let (y1, y2) = x.share();

    // let mut sketches = vec![];
    // sketches.push(keys[0].sketch_at(&vec1, &mut seed.to_rng()));
    // sketches.push(keys[1].sketch_at(&vec2, &mut seed.to_rng()));

    // let level_zero: usize = (level - 2).into();
    // let state0 = mpc::MulState::new(false, keys[0].triples.clone(), &keys[0].mac_key, &keys[0].mac_key2, &y1.clone(), &sketches[0], level_zero);
    // let state1 = mpc::MulState::new(true, keys[1].triples.clone(), &keys[1].mac_key, &keys[1].mac_key2, &y2.clone(), &sketches[1], level_zero);

    // let corshare0 = state0.cor_share();
    // let corshare1 = state1.cor_share();

    // let cor = mpc::MulState::cor(&corshare0, &corshare1);

    // let outshare0 = state0.out_share(&cor);
    // let outshare1 = state1.out_share(&cor);

    // assert!(mpc::MulState::verify(&outshare0, &outshare1));
}
fn main() {
    mpc_test();
}
