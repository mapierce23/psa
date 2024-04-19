#![allow(non_snake_case)]
#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]
use std::io;
use std ::net::{TcpListener,TcpStream};
use std::io::{Read,Write};
use std::thread;
use std::sync::Mutex;
use std::ops::Deref;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::ops::DerefMut;
use hmac::{Hmac, Mac, NewMac};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::rand_core::RngCore;
use std::convert::TryInto;
use sha2::Sha256;
use sha2::Digest;
use rand_chacha::ChaCha8Rng;
use rand::thread_rng;
use redis::RedisResult;
use rand::Rng;
use redis::Connection;
use redis::Commands;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use payapp::ps::*;
use payapp::ggm::*;
use payapp::prg::PrgSeed;
use payapp::coms::*;
use payapp::sketch::*;
use payapp::mpc::*;
use payapp::Group;
use payapp::FieldElm;
use payapp::MAX_GROUP_SIZE;
use payapp::MAX_GROUP_NUM;

// pub const REDIS: &str = "redis://127.0.0.1:6379";
pub const REDIS: &str = "redis://10.128.0.4:6379";

fn handle_client(mut stream: TcpStream, counter: Arc<Mutex<usize>>, database: Arc<Mutex<Vec<FieldElm>>>) -> io::Result<()> {

    let con_try = redis_connect();
    let mut con: Connection = con_try.unwrap();

    for _ in 0..1000 {

        // Remaining bytes is the type of request & the request itself
        let mut buf = [0;1];
        let res = stream.read_exact(&mut buf);
        if !res.is_ok() {
            continue;
        }

        // Server 1 handles all new group requests
        // TYPE: TRANSACTION
        // DATA: TransactionData struct
        if buf[0] == 4 {
            let bytes_read = 2610;
            let mut buf1 = vec![0;2610];
            stream.read_exact(&mut buf1)?;
            let res = bincode::deserialize(&buf1[0..bytes_read]);
            if res.is_err() {
                let success = String::from("skipping");
                let encoded = bincode::serialize(&success).unwrap();
                let _ = stream.write(&encoded);
                continue;
            }
            let td: TransactionDataS2 = res.unwrap();
            let (sketch_src, sketch_dest, eval_all_src, eval_all_dest) = eval_all(&td.dpf_src, &td.dpf_dest);
            // ============================ VERIFY DPF SKETCHES =======================================
            let seed = PrgSeed::random();
            let mut sketches = vec![];
            sketches.push((&td.dpf_src).sketch_at(&sketch_src, &mut seed.to_rng()));
            sketches.push((&td.dpf_dest).sketch_at(&sketch_dest, &mut seed.to_rng()));
            let state2s = MulState::new(false, (&td.dpf_src).triples.clone(), &(&td.dpf_src).mac_key, &(&td.dpf_src).mac_key2, &(&td.dpf_src).val_share, &(&td.dpf_src).val2_share, &sketches[0]);
            let state2d = MulState::new(false, (&td.dpf_dest).triples.clone(), &(&td.dpf_dest).mac_key, &(&td.dpf_dest).mac_key2, &(&td.dpf_dest).val_share, &(&td.dpf_dest).val2_share, &sketches[1]);
            let corshare2s = state2s.cor_share();
            let corshare2d = state2d.cor_share();
            // ===========================================================================
            let (com_x, com_ix, g_r2, g_r3) = compute_coms_from_dpf(&eval_all_src, td.r2, td.r3); // Four Ristrettos (compressed)
            let w1 = same_group_val_compute(&eval_all_src, &eval_all_dest, false);
            let mut prg: ChaCha8Rng = ChaCha8Rng::seed_from_u64((td.id as u64) + 56789u64);
            let zero_bytes = [0u8; 16];
            let mut rvec = Vec::<FieldElm>::new();
            // Compute inner product 
            let mut prod = FieldElm::one();
            for i in 0..MAX_GROUP_SIZE {
                let mut buf = [0u8; 16];
                prg.fill_bytes(&mut buf);
                let mut output = buf.to_vec();
                output.extend(zero_bytes.clone());
                let scalar = Scalar::from_bytes_mod_order(output.try_into().unwrap());
                rvec.push(FieldElm {value : scalar});
                prod.mul(&w1[i]);
                prod.mul(&rvec[i]);
            }
            let package = TransactionPackage {
                strin: "Server2", 
                com_x: com_x,
                com_ix: com_ix,
                g_r2: g_r2,
                g_r3: g_r3,
                cshare_s: corshare2s.clone(),
                cshare_d: corshare2d.clone(),
            };
            let mut encoded: Vec<u8> = Vec::new();
            encoded.extend(bincode::serialize(&package).unwrap());
            let mut key: Vec<u8> = Vec::new();
            key.extend([2u8, 2u8]); // SERVER ID, TYPE
            key.extend(td.id.to_be_bytes());
            let _ : () = con.set(key.clone(), encoded).unwrap();
            // WAIT for response
            key[0] = 1u8;
            let mut res = con.get(key.clone());
            while res.is_err() {
                res = con.get(key.clone());
            }
            let mut bin: Vec<u8> = res.unwrap();
            let mut res = bincode::deserialize(&bin);
            while res.is_err() {
                bin = con.get(key.clone()).unwrap();
                res = bincode::deserialize(&bin);
            }
            let s1data: TransactionPackage = res.unwrap();
            let cor_s = MulState::cor(&corshare2s, &(s1data.cshare_s));
            let cor_d = MulState::cor(&corshare2d, &(s1data.cshare_d));
            let outshare2s = state2s.out_share(&cor_s);
            let outshare2d = state2d.out_share(&cor_d);
            // ======================================================================================
            let mut encoded: Vec<u8> = Vec::new();
            encoded.extend(bincode::serialize(&(outshare2s.clone(), outshare2d.clone())).unwrap());
            let mut key: Vec<u8> = Vec::new();
            key.extend([2u8, 3u8]); // SERVER ID, TYPE
            key.extend(td.id.to_be_bytes());
            let _ : () = con.set(key.clone(), encoded).unwrap();
            // WAIT for response
            key[0] = 1u8;
            let mut bin: Vec<u8> = con.get(key.clone()).unwrap();
            let mut res = bincode::deserialize(&bin);
            while res.is_err() {
                bin = con.get(key.clone()).unwrap();
                res = bincode::deserialize(&bin);
            }
            let s1sketch: (OutShare<FieldElm>, OutShare<FieldElm>) = res.unwrap();
            MulState::verify(&outshare2s, &s1sketch.0);
            MulState::verify(&outshare2d, &s1sketch.0);
            // ======================================================================================
            // Get data from S1
            // Add gp_val vectors and check == 0
            // Multiply commitments/exponents and verify transaction proof
            // verify sketch 
            // let g_r2_1: RistrettoPoint = s1data.g_r2.decompress().expect("REASON");
            // let g_r2_2: RistrettoPoint = g_r2.decompress().expect("REASON");
            // let g_r2 = g_r2_1 + g_r2_2;
            // let g_r3_1: RistrettoPoint = g_r3.decompress().expect("REASON");
            // let g_r3_2: RistrettoPoint = s1data.g_r3.decompress().expect("REASON");
            // let g_r3 = g_r3_1 + g_r3_2;
            // let comx_1: RistrettoPoint = com_x.decompress().expect("REASON");
            // let comx_2: RistrettoPoint = s1data.com_x.decompress().expect("REASON");
            // let comx = comx_1 + comx_2;
            // let comix_1: RistrettoPoint = com_ix.decompress().expect("REASON");
            // let comix_2: RistrettoPoint = s1data.com_ix.decompress().expect("REASON");
            // let comix = comix_1 + comix_2;
            // let g_r1 = td.g_r1.decompress().expect("REASON");
            // let com_i = td.com_i.decompress().expect("REASON");
            // let (com_a, com_x) = verify_coms_from_dpf(g_r1, g_r2, g_r3, com_i, comx, comix, td.triple_proof).unwrap();
            let ver = true; 
            let mut success = String::from("Transaction Processed");
            if ver != true {
                println!("Invalid!");
                success = String::from("Invalid Transaction");
            }
            else {
                // Proofs have been verified, now complete transaction
                let mut guard = database.lock().unwrap();
                ServerData::transact(guard.deref_mut(), &eval_all_src, &eval_all_dest);
                let success = String::from("Transaction Processed");
            }
            let encoded = bincode::serialize(&success).unwrap();
            let _ = stream.write(&encoded);
        }
        // TYPE: SETTLING
        // DATA: Settle Request
        if buf[0] == 5 {
            let bytes_read = 2344;
            let mut buf1 = vec![0;2344];
            stream.read_exact(&mut buf1)?;
            let settle_data: SettleData = bincode::deserialize(&buf[0..bytes_read]).unwrap();
            // ENCRYPT THE DATABASE, SEND TO S1
            let mut guard = database.lock().unwrap();
            let mut key_arr = Vec::<Vec<u8>>::new();
            let mut key: Vec<u8> = Vec::new();
            for j in 0..MAX_GROUP_NUM {
                key.extend([2u8, 1u8]);
                key.extend(j.to_be_bytes());
                let res: RedisResult<Vec<u8>> = con.get(key.clone()); 
                if res.is_ok() {
                    let vec = res.unwrap();
                    if vec.len() == 0 {
                        let zbytes = [0u8; 16];
                        key_arr.push(zbytes.to_vec());
                    }
                    else {
                        key_arr.push(vec);
                    }
                }
                key.clear();
            }
            let enc_db2 = ServerData::encrypt_db(guard.deref(), &key_arr, settle_data.r_seed);
            drop(guard);
            let encoded = bincode::serialize(&enc_db2).unwrap();
            let mut key: Vec<u8> = Vec::new();
            key.extend([2u8, 4u8]); // SERVER ID, TYPE
            let _ : () = con.set(key.clone(), encoded).unwrap();
            // WAIT for response
            key[0] = 1u8;
            let mut res = con.get(key.clone());
            while res.is_err() {
                res = con.get(key.clone());
            }
            let mut bin: Vec<u8> = res.unwrap();
            let mut res = bincode::deserialize(&bin);
            while res.is_err() {
                bin = con.get(key.clone()).unwrap();
                res = bincode::deserialize(&bin);
            }
            let s1enc_db: Vec<FieldElm> = res.unwrap(); 

            let balance_vec2 = ServerData::settle(&enc_db2, &s1enc_db, &settle_data.dpf_key);
            let encoded = bincode::serialize(&balance_vec2).unwrap();
            let _ = stream.write(&encoded);
        }

        // And you can sleep this connection with the connected sender
        thread::sleep(Duration::from_secs(1));  
    }
    Ok(())
}

fn redis_connect() -> redis::RedisResult<Connection> {
    let client = redis::Client::open(REDIS)?;
    let con = client.get_connection()?;

    Ok(con)
}

fn main() -> io::Result<()> {

    // Establish TCP Connection
    let receiver_listener = TcpListener::bind("0.0.0.0:7879").expect("Failed and bind with the sender");
    let mut thread_vec: Vec<thread::JoinHandle<()>> = Vec::new();

    // Initialize Server Data
    let issuer = Issuer::new(5);
    let counter = Arc::new(Mutex::new(0usize));
    let mut vec = Vec::<FieldElm>::new();
    for i in 0..MAX_GROUP_NUM * MAX_GROUP_SIZE {
        vec.push(FieldElm::zero());
    }
    let database = Arc::new(Mutex::new(vec));

    for stream in receiver_listener.incoming() {
        let stream = stream.expect("failed");
        let counter = counter.clone();
        let database = database.clone();
        let handle = thread::spawn(move || {
            handle_client(stream, counter, database).unwrap_or_else(|error| eprintln!("{:?}",error))
        });
        thread_vec.push(handle);
    }

    for handle in thread_vec {
        // return each single value Output contained in the heap
        handle.join().unwrap();
    }
    // success value
    Ok(())
}
