#[macro_use]
extern crate zkp;

pub mod ggm;
pub mod dpf;
pub mod coms;
pub mod ps;
pub mod prg;
pub mod mpc;
pub mod sketch;
mod field;

#[macro_use]
extern crate lazy_static;
use rsa::{RsaPrivateKey, RsaPublicKey};
use rand_pcg::Pcg64;
use rand::rngs::OsRng;
use rsa::rand_core::SeedableRng;


pub use crate::field::FieldElm;
//pub use crate::rpc::CollectorClient;

pub const MAX_GROUP_SIZE: usize = 10;
pub const MAX_GROUP_NUM: usize = 50;
pub const DPF_DOMAIN: usize = 10; // 9 = 2^8 = 256 // about 60 AES evals
pub const SETTLE_DOMAIN: usize = 8; // 9 = 2^8 = 256 // about 60 AES evals
pub const SETTLE_SIZE: usize = 233;
pub const CRED_REQUEST_1: usize = 2648; 
pub const TRANSACT_REQ_1: usize = 2824 + 136 * 9 - 38 * 1;
pub const TRANSACT_REQ_2: usize = 2344 - 38 * 1;


// Additive group, such as (Z_n, +)
pub trait Group {
    fn zero() -> Self;
    fn one() -> Self;
    fn negate(&mut self);
    fn reduce(&mut self);
    fn add(&mut self, other: &Self);
    fn add_lazy(&mut self, other: &Self);
    fn mul(&mut self, other: &Self);
    fn mul_lazy(&mut self, other: &Self);
    fn sub(&mut self, other: &Self);
}

pub trait Share: Group + prg::FromRng + Clone {
    fn random() -> Self {
        let mut out = Self::zero();
        out.randomize();
        out
    }

    fn share(&self) -> (Self, Self) {
        let mut s0 = Self::zero();
        s0.randomize();
        let mut s1 = self.clone();
        s1.sub(&s0);

        (s0, s1)
    }

    fn share_random() -> (Self, Self) {
        (Self::random(), Self::random())
    }
}

pub fn u32_to_bits(nbits: u8, input: u32) -> Vec<bool> {
    assert!(nbits <= 32);

    let mut out: Vec<bool> = Vec::new();
    for i in 0..nbits {
        let bit = (input & (1 << i)) != 0;
        out.push(bit);
    }

    out
}

pub fn my_u32_to_bits(nbits: u8, input: u32) -> Vec<bool> {
    assert!(nbits <= 32);

    let mut out: Vec<bool> = Vec::new();
    for i in 0..nbits {
        let bit = (input & (1 << i)) != 0;
        out.push(bit);
    }
    let mut out_real: Vec<bool> = Vec::new();
    for i in 0..nbits - 1 {
        let idx = (nbits as usize) - (i as usize);
        out_real.push(out[idx - 2]);
    }
    out_real.push(false);
    out_real
}

pub fn string_to_bits(s: &str) -> Vec<bool> {
    let mut bits = vec![];
    let byte_vec = s.to_string().into_bytes();
    for byte in &byte_vec {
        let mut b = crate::u32_to_bits(8, (*byte).into());
        bits.append(&mut b);
    }
    bits
}

fn bits_to_u8(bits: &[bool]) -> u8 {
    assert_eq!(bits.len(), 8);
    let mut out = 0u8;
    for i in 0..8 {
        let b8: u8 = bits[i].into();
        out |= b8 << i;
    }

    out
}

pub fn bits_to_string(bits: &[bool]) -> String {
    assert!(bits.len() % 8 == 0);

    let mut out: String = "".to_string();
    let byte_len = bits.len() / 8;
    for b in 0..byte_len {
        let byte = &bits[8 * b..8 * (b + 1)];
        let ubyte = bits_to_u8(&byte);
        out.push_str(std::str::from_utf8(&[ubyte]).unwrap());
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn share() {
        let val = FieldElm::random();
        let (s0, s1) = val.share();
        let mut out = FieldElm::zero();
        out.add(&s0);
        out.add(&s1);
        assert_eq!(out, val);
    }

    #[test]
    fn to_bits() {
        let empty: Vec<bool> = vec![];
        assert_eq!(u32_to_bits(0, 7), empty);
        assert_eq!(u32_to_bits(1, 0), vec![false]);
        assert_eq!(u32_to_bits(2, 0), vec![false, false]);
        assert_eq!(u32_to_bits(2, 3), vec![true, true]);
        assert_eq!(u32_to_bits(2, 1), vec![true, false]);
        assert_eq!(u32_to_bits(12, 65535), vec![true; 12]);
    }

    #[test]
    fn to_string() {
        let empty: Vec<bool> = vec![];
        assert_eq!(string_to_bits(""), empty);
        let avec = vec![true, false, false, false, false, true, true, false];
        assert_eq!(string_to_bits("a"), avec);

        let mut aaavec = vec![];
        for _i in 0..3 {
            aaavec.append(&mut avec.clone());
        }
        assert_eq!(string_to_bits("aaa"), aaavec);
    }

    #[test]
    fn to_from_string() {
        let s = "basfsdfwefwf";
        let bitvec = string_to_bits(s);
        let s2 = bits_to_string(&bitvec);

        assert_eq!(bitvec.len(), s.len() * 8);
        assert_eq!(s, s2);
    }
}
