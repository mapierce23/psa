#![allow(non_snake_case)]
#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]
extern crate crypto;
use aes::{ Aes128, Block, 
    cipher::{ BlockEncrypt, KeyInit, KeyIvInit, StreamCipher,
        generic_array::{GenericArray, typenum::{U8}}
    }
};
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
use dpf::DPF_KEY_SIZE;
use dpf::DpfKey;

use payapp::sketch::*;
use payapp::coms::*;
use payapp::prg::*;
use payapp::ps::*;
use payapp::ggm::*;

lazy_static! {
    pub static ref GEN_G: RistrettoPoint =
        RistrettoPoint::hash_from_bytes::<Sha512>(b"CMZ Generator A");
    pub static ref GEN_H: RistrettoPoint = dalek_constants::RISTRETTO_BASEPOINT_POINT;
}

const AES_KEY_SIZE: usize = 16;
fn mpc_test() {

    let G = RistrettoPoint::hash_from_bytes::<Sha512>(b"CMZ Generator A");
    let x = G.compress();
    let mut encoded: Vec<u8> = Vec::new();
    encoded.push(2u8);
    encoded.extend(bincode::serialize(&x).unwrap());
    println!("{:?}", encoded.len());
    let nbits = 12; // 2048
    let alpha_s = my_u32_to_bits(nbits, 30);
    let betas = vec![
        FieldElm::from(0u32),
        FieldElm::from(0u32),
        FieldElm::from(0u32),
        FieldElm::from(0u32),
        FieldElm::from(0u32),
        FieldElm::from(0u32),
        FieldElm::from(0u32),
        FieldElm::from(0u32),
        FieldElm::from(0u32),
        FieldElm::from(0u32),
        FieldElm::from(1u32),
    ];
    let beta_last = FieldElm::from(0u32);
    let keys = SketchDPFKey::gen(&alpha_s, &betas, &beta_last);
    // let keys_d = SketchDPFKey::gen(&alpha_d, &betas, &beta_last);
    let mut encoded: Vec<u8> = Vec::new();
    encoded.push(2u8);
    encoded.extend(bincode::serialize(&keys[0].key).unwrap());
    println!("{:?}", encoded.len());
    
    // let seed = PrgSeed::random();
    // println!("Eval!");

    let now = SystemTime::now();
    let vec1 = keys[0].key.eval_all();
    let vec2 = keys[1].key.eval_all(); 
    println!("{:?}", vec1.len());
    for i in 0..vec2.len() {
        let mut sum = FieldElm::zero();
        sum.add(&vec1[i].0);
        sum.add(&vec2[i].0);
        if sum != FieldElm::zero() {
            println!("{:?}", i);
            println!("{:?}", sum);
        }
    }
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

    let key = GenericArray::from([0u8; AES_KEY_SIZE]);
    let m_key = &[0u8; 16];
    let aes =  Aes128::new(&key);
    let mut buf = [0; AES_BLOCK_SIZE * 8];
    
    let now = SystemTime::now();
    for j in 0..21 {
        let mut ctr = FixedKeyPrgStream::load(m_key);
        for i in 0..3 {
            FixedKeyPrgStream::store(ctr, &mut buf[0..AES_BLOCK_SIZE]);
            let count_bytes = buf;
            let mut gen = GenericArray::from_mut_slice(&mut buf[0..AES_BLOCK_SIZE]);
            aes.encrypt_block(&mut gen);
            // Compute:   AES_0000(ctr) XOR ctr
            buf
                .iter_mut()
                .zip(count_bytes.iter())
                .for_each(|(x1, x2)| *x1 ^= *x2);

            ctr = FixedKeyPrgStream::inc_be(ctr);
        }
    }   

    // match now.elapsed() {
    //     Ok(elapsed) => {
    //         // it prints '2'
    //         println!("{:?}", elapsed.as_nanos());
    //     }
    //     Err(e) => {
    //         // an error occurred!
    //         println!("Error: {e:?}");
    //     }
    // }



    // let now = SystemTime::now();
    // let vec1_it = keys[0].key.eval_all_iter();
    // let vec2_it = keys[1].key.eval_all_iter();
    // println!("{:?}", vec1_it.len());
    // match now.elapsed() {
    //     Ok(elapsed) => {
    //         // it prints '2'
    //         println!("{}", elapsed.as_nanos());
    //     }
    //     Err(e) => {
    //         // an error occurred!
    //         println!("Error: {e:?}");
    //     }
    // }

}
fn main() {
    mpc_test();
}
