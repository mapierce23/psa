#![allow(non_snake_case)]
#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]
use std::net::TcpStream;
use std::io::{self, Read, Write};
use zkp::CompactProof;
use zkp::ProofError;
use zkp::Transcript;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::constants as dalek_constants;
use curve25519_dalek::traits::Identity;
use sha2::Sha512;
use payapp::sketch::SketchDPFKey;
use std::convert::TryInto;
use std::ops::Neg;
use std::time::{Duration, SystemTime};
use rand::Rng;
use lazy_static::lazy_static;

use payapp::ps::*;
use payapp::ggm::*;
use payapp::coms::*;
use payapp::Group;
use payapp::u32_to_bits;
use payapp::my_u32_to_bits;
use payapp::FieldElm;
use payapp::dpf::DPFKey;
use payapp::MAX_GROUP_SIZE;
use payapp::MAX_GROUP_NUM;
use payapp::DPF_DOMAIN;

lazy_static! {
    pub static ref GEN_G: RistrettoPoint =
        RistrettoPoint::hash_from_bytes::<Sha512>(b"CMZ Generator A");
    pub static ref GEN_H: RistrettoPoint = dalek_constants::RISTRETTO_BASEPOINT_POINT;
}

fn main() -> io::Result<( )> {

    let mut leader = GpLeaderData::new(MAX_GROUP_SIZE);
    let mut stream1 = TcpStream::connect("127.0.0.1:7878")?;
    let mut stream2 = TcpStream::connect("127.0.0.1:7879")?;

    // GROUP SETUP
    // Send group creation request to the server
    let mut encoded: Vec<u8> = Vec::new();
    let prf_keys = (4u64, 5u64);
    let key_bytes1 = rand::thread_rng().gen::<[u8; 16]>();
    let key_bytes2 = rand::thread_rng().gen::<[u8; 16]>();
    let prf_keys = (key_bytes1.to_vec(), key_bytes2.to_vec());
    encoded.push(1u8);
    encoded.extend(bincode::serialize(&prf_keys).unwrap());
    stream1.write(&encoded).expect("failed to write");

    // The server responds with a list of account IDs and a public key
    let mut buf = [0;8192];
    let mut bytes_read = 0;
    while bytes_read == 0 {
        bytes_read = stream1.read(&mut buf)?;
    }
    let (aids, pubkey): (Vec<u64>, IssuerPubKey) = bincode::deserialize(&buf[0..bytes_read]).unwrap();
    let creds = leader.group_setup(aids, &stream1, pubkey.clone())?;

    // The credential is the registration token. Each group member submits their
    // reg token to the server in exchange for a group token.  
    let (z3, showmsg) = show_blind345_5::show(&creds[5], &pubkey);
    let mut encoded: Vec<u8> = Vec::new();
    encoded.push(3u8);
    encoded.extend(bincode::serialize(&showmsg).unwrap());
    stream1.write(&encoded).expect("failed to write");
    let mut buf = [0;8192];
    let mut bytes_read = 0;
    while bytes_read == 0 {
        bytes_read = stream1.read(&mut buf)?;
    }
    let group_token: GroupToken = bincode::deserialize(&buf[0..bytes_read]).unwrap();
    let priv_token = GroupTokenPriv {
        prf_keys: prf_keys.clone(),
        token: group_token.clone(), 
        z3: z3, 
        aid: creds[5].m[3],
    };
    let mut tokens = Vec::<GroupToken>::new();
    tokens.push(group_token.clone());
    // TRANSACTION TIME
    // DPF Keys
    let mut count: u8 = 1;
    for i in 0..5 {
        let now = SystemTime::now();
        let bytes = priv_token.aid.to_bytes();
        let (int_bytes, rest) = bytes.split_at(std::mem::size_of::<u32>());
        let src: u32 = u32::from_le_bytes(int_bytes.try_into().unwrap());
        let betas = vec![
            FieldElm::from(0u32),
            FieldElm::from(0u32),
            FieldElm::from(0u32),
            FieldElm::from(0u32),
            FieldElm::from(0u32),
            FieldElm::from(0u32),
            FieldElm::from(3u32),
        ];
        let a_src = my_u32_to_bits(DPF_DOMAIN.try_into().unwrap(), src);
        let a_dest = my_u32_to_bits(DPF_DOMAIN.try_into().unwrap(), src + 1);
        let beta_last = FieldElm::from(0u32);
        let keys_src = SketchDPFKey::gen(&a_src, &betas, &beta_last);
        let keys_dest = SketchDPFKey::gen(&a_dest, &betas, &beta_last);

        // Randomness
        // =======================================================
        let mut rng = rand::thread_rng();
        let r1 = Scalar::random(&mut rng);
        let r2_1 = Scalar::random(&mut rng);
        let r2_2 = Scalar::random(&mut rng);
        let r2 = r2_1 + r2_2;
        let r3_1 = Scalar::random(&mut rng);
        let r3_2 = Scalar::random(&mut rng);
        let r3 = r3_1 + r3_2;
        // =======================================================
        let G: &RistrettoPoint = &GEN_G;
        let H: &RistrettoPoint = &GEN_H;
        let nG = G.clone().neg();
        let nH = H.clone().neg();
        let id = Scalar::one();
        let a_sc = Scalar::from(src);
        let b_sc = Scalar::from(3u32);
        let v1 = G * r1;
        let v2 = G * r2;
        let v3 = G * r3;
        let e1 = G * a_sc + H * r1;
        let e2 = G * b_sc + H * r2;
        let ab_sc = a_sc * b_sc;
        let e3 = G * ab_sc + H * r3;
        let tau = a_sc * r2;
        let ne3 = e3.clone().neg();
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
        let mut transcript = Transcript::new(b"Transaction Proof");
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
                a: &a_sc,
                id: &id,
                tau: &tau,
            },
        )
        .0;
        let token_ci = group_token.cm_aid.decompress().expect("REASON");
        let token_P = group_token.P.decompress().expect("REASON");
        let mut transcript = Transcript::new(b"Group Token Proof");
        let token_pf = token::prove_compact(
            &mut transcript,
            token::ProveAssignments {
                G: &G,
                H: &H,
                P: &token_P,
                Ti: &token_ci,
                Ci: &e1,
                i: &a_sc,
                rt: &priv_token.z3,
                rc: &r1,
            },
        )
        .0;
        // Package data to send to the servers 
        let transact_data1 = TransactionData {
            tokens: tokens.clone(),
            id: count,
            dpf_src: keys_src[0].clone(),
            dpf_dest: keys_dest[0].clone(),
            g_r1: v1.compress(),
            r2: r2_1,
            r3: r3_1,
            com_i: e1.compress(),
            triple_proof: transact_pf.clone(),
            token_proof: token_pf.clone(),
        };
        let transact_data2 = TransactionData {
            tokens: tokens.clone(),
            id: count,
            dpf_src: keys_src[1].clone(),
            dpf_dest: keys_dest[1].clone(),
            g_r1: v1.compress(),
            r2: r2_2,
            r3: r3_2,
            com_i: e1.compress(),
            triple_proof: transact_pf.clone(),
            token_proof: token_pf.clone(),
        };
        // Send to S1
        let mut encoded1: Vec<u8> = Vec::new();
        encoded1.push(4u8);
        encoded1.extend(bincode::serialize(&transact_data1).unwrap());
        stream1.write(&encoded1).expect("failed to write");
        // Send to S2
        let mut encoded2: Vec<u8> = Vec::new();
        encoded2.push(4u8);
        encoded2.extend(bincode::serialize(&transact_data2).unwrap());
        stream2.write(&encoded2).expect("failed to write");

        // Make sure transaction was valid 
        let mut buf = [0;8192];
        let mut bytes_read = 0;
        while bytes_read == 0 {
            bytes_read = stream1.read(&mut buf)?;
        }
        let msg: String = bincode::deserialize(&buf[0..bytes_read]).unwrap();
        if msg != String::from("Transaction Processed") {
            println!("Uh oh! Submitted invalid transaction.");
        }
        else {
            println!("yay from S1!");
        }
        let mut buf = [0;8192];
        let mut bytes_read = 0;
        while bytes_read == 0 {
            bytes_read = stream2.read(&mut buf)?;
        }
        let msg: String = bincode::deserialize(&buf[0..bytes_read]).unwrap();
        if msg != String::from("Transaction Processed") {
            println!("Uh oh! Submitted invalid transaction.");
        }
        else {
            println!("yay from S2!");
        }
        count += 1;
    }

    // =======================================================================
    // SETTLING REQUEST
    // =======================================================================
    let group_num = 2;
    println!("{:?}", group_num);
    // DPF Key generation
    let alpha_bits = u32_to_bits(6, group_num);
    let values = vec![
        FieldElm::from(0u32),
        FieldElm::from(0u32),
        FieldElm::from(0u32),
        FieldElm::from(1u32),
        FieldElm::from(0u32),
    ];
    let (key1, key2) = DPFKey::gen(&alpha_bits, &values, &FieldElm::zero());
    let r_bytes = rand::thread_rng().gen::<[u8; 16]>();
    // Send to S1
    let s1_data = SettleData {
        dpf_key: key1,
        r_seed: r_bytes.to_vec(),
    };
    let mut encoded1: Vec<u8> = Vec::new();
    encoded1.push(5u8);
    encoded1.extend(bincode::serialize(&s1_data).unwrap());
    stream1.write(&encoded1).expect("failed to write");
    // Send to S2
    let s2_data = SettleData {
        dpf_key: key2,
        r_seed: r_bytes.to_vec(),
    };
    let mut encoded2: Vec<u8> = Vec::new();
    encoded2.push(5u8);
    encoded2.extend(bincode::serialize(&s2_data).unwrap());
    stream2.write(&encoded2).expect("failed to write");

    let mut buf1 = [0;8192];
    let mut bytes_read1 = 0;
    while bytes_read1 == 0 {
        bytes_read1 = stream1.read(&mut buf1)?;
    }
    let mut buf2 = [0;8192];
    let mut bytes_read2 = 0;
    while bytes_read2 == 0 {
        bytes_read2 = stream2.read(&mut buf2)?;
    }
    let bv_1: Vec<FieldElm> = bincode::deserialize(&buf1[0..bytes_read1]).unwrap();
    let bv_2: Vec<FieldElm> = bincode::deserialize(&buf2[0..bytes_read2]).unwrap();
    let mut bv = Vec::<FieldElm>::new();
    for i in 0..MAX_GROUP_SIZE {
        let mut sum = FieldElm::zero();
        sum.add(&bv_1[i]);
        sum.add(&bv_2[i]);
        bv.push(sum);
    }
    let bv = GroupTokenPriv::decrypt_db(bv.clone(), key_bytes1.to_vec(), key_bytes2.to_vec(), r_bytes.to_vec());
    // =========================================================================
    Ok(())
}

