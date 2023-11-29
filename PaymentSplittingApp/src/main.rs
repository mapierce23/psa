#![allow(non_snake_case)]


use crate::dpf::*;
use crate::u32_to_bits;
use crate::FieldElm;
use crate::Group;


fn main() {
	let alpha_bits = u32_to_bits(5, 21);
	let non_alpha_bits = u32_to_bits(5, 22);
	let values = vec![FieldElm::one(); alpha_bits.len()-1];
	let mul_val = FieldElm::from(32u32);

	let (key0, key1) = DPFKey::<FieldElm, FieldElm>::gen(&alpha_bits, &values, &FieldElm::one());
    let encoded: Vec<u8> = bincode::serialize(&key0).unwrap();
    let decoded: DPFKey<FieldElm, FieldElm> = bincode::deserialize(&encoded[..]).unwrap();

	let mut eval0 = key0.eval(&alpha_bits[0..4].to_vec());
	let mut eval1 = key1.eval(&alpha_bits[0..4].to_vec());
	let mut tmp = FieldElm::zero();
	eval0.0[2].mul(&mul_val);
	eval1.0[2].mul(&mul_val);
	tmp.add(&eval0.0[2]);
	tmp.add(&eval1.0[2]);
	assert_eq!(tmp, FieldElm::one());

}