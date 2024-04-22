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

fn handle_client(mut stream: TcpStream, issuer: Issuer, counter: Arc<Mutex<usize>>, database: Arc<Mutex<Vec<FieldElm>>>, prf_keys: Arc<Mutex<Vec<Vec<u8>>>>, mac: &Hmac<Sha256>, streams: &u32) -> io::Result<()> {

    let mut server_data = ServerData::new(issuer);
    let con_try = redis_connect();
    let mut con: Connection = con_try.unwrap();

    for _ in 0..1000 {

        // Remaining bytes is the type of request & the request itself
        let mut buf = [0;1];
        let res = stream.read_exact(&mut buf);
        if !res.is_ok() {
            continue;
        }

        // if bytes_read == 0 {
        //     continue;
        // }

        // TYPE: NEW GROUP REQUEST
        // Data: PRF Keys
        if buf[0] == 1 {
            let bytes_read = 48;
            let mut buf1 = [0;48];
            stream.read_exact(&mut buf1)?;
            let mut guard = counter.lock().unwrap();
            let index = guard.deref();
            let group_num = (*index) / MAX_GROUP_SIZE; // GROUP NUM
            let decoded: (Vec<u8>, Vec<u8>) = bincode::deserialize(&buf1[0..bytes_read]).unwrap();
            // RECORD THIS SERVER'S PRF KEY
            let mut key_guard = prf_keys.lock().unwrap();
            (*key_guard).remove(MAX_GROUP_NUM - 1);
            (*key_guard).insert(group_num, decoded.0);

            // SEND S2 ITS PRF KEY
            let mut key: Vec<u8> = Vec::new();
            key.extend([2u8, 1u8]); // SERVER ID, TYPE
            key.extend(group_num.to_be_bytes()); 
            let _ : () = con.set(key.clone(), decoded.1).unwrap();

            let (aids, pubkey) = server_data.setup_new_group(guard.deref());
            let encoded = bincode::serialize(&(aids, pubkey)).unwrap();
            let _ = stream.write(&encoded);
            *guard += MAX_GROUP_SIZE;
        }
        // TYPE: SETUP REGISTRATION TOKENS
        // DATA: Vector of Credential Requests
        if buf[0] == 2 {
            let bytes_read = 2648;
            let mut buf1 = [0;2648];
            let res = stream.read_exact(&mut buf1);
            if !res.is_ok() {
                println!("uh oh!");
            }
            let decoded: Vec<issue_blind124_5::CredentialRequest> = bincode::deserialize(&buf1[0..bytes_read]).unwrap();
            let reg_tokens = server_data.setup_reg_tokens(decoded);
            let encoded = bincode::serialize(&reg_tokens).unwrap();
            println!("sending back... {:?}", encoded.len());
            let _ = stream.write(&encoded);
        }

        // TYPE: USER REGISTRATION
        // DATA: Show Message
        if buf[0] == 3 {
            let bytes_read = 264;
            let mut buf1 = [0;264];
            stream.read_exact(&mut buf1)?;
            let decoded: show_blind345_5::ShowMessage = bincode::deserialize(&buf1[0..bytes_read]).unwrap();
            let group_token = server_data.register_user(decoded, &mac).unwrap();
            let encoded = bincode::serialize(&group_token).unwrap();
            let _ = stream.write(&encoded);
        }

        // TYPE: TRANSACTION
        // DATA: TransactionData struct
        if buf[0] == 4 {
            let bytes_read = 3096;
            let mut buf1 = vec![0;3096];
            stream.read_exact(&mut buf1)?;
            // println!("Transaction, bytes read: {:?}", bytes_read);
            let mut sum = 0;
            let td: TransactionData = bincode::deserialize(&buf1[0..bytes_read]).unwrap();
            let (sketch_src, sketch_dest, eval_all_src, eval_all_dest) = eval_all(&td.dpf_src, &td.dpf_dest);
            // VERIFY DPF SKETCHES
            let seed = PrgSeed::random();
            let mut sketches = vec![];
            sketches.push((&td.dpf_src).sketch_at(&sketch_src, &mut seed.to_rng()));
            sketches.push((&td.dpf_dest).sketch_at(&sketch_dest, &mut seed.to_rng()));
            let state1s = MulState::new(false, (&td.dpf_src).triples.clone(), &(&td.dpf_src).mac_key, &(&td.dpf_src).mac_key2, &(&td.dpf_src).val_share, &(&td.dpf_src).val2_share, &sketches[0]);
            let state1d = MulState::new(false, (&td.dpf_dest).triples.clone(), &(&td.dpf_dest).mac_key, &(&td.dpf_dest).mac_key2, &(&td.dpf_dest).val_share, &(&td.dpf_dest).val2_share, &sketches[1]);
            let corshare1s = state1s.cor_share();
            let corshare1d = state1d.cor_share();
            // ===============================================================
            let mut sum = 0;
            let ver = true; 
            // verify_group_tokens(td.token_proof, td.tokens, td.com_i, &mac);
            let (com_x, com_ix, g_r2, g_r3) = compute_coms_from_dpf(&eval_all_src, td.r2, td.r3); // Four Ristrettos (compressed)
            let w1 = same_group_val_compute(&eval_all_src, &eval_all_dest, true);
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
                    strin: "Server1",
                    com_x: com_x,
                    com_ix: com_ix,
                    g_r2: g_r2,
                    g_r3: g_r3,
                    cshare_s: corshare1s.clone(),
                    cshare_d: corshare1d.clone(),
                };
            let mut encoded: Vec<u8> = Vec::new();
            encoded.extend(bincode::serialize(&package).unwrap());
            let mut key: Vec<u8> = Vec::new();
            key.extend([1u8, 2u8]); // SERVER ID, TYPE
            key.extend(td.id.to_be_bytes());
            let _ : () = con.set(key.clone(), encoded).unwrap();
            // WAIT for response
            key[0] = 2u8;
            let mut bin: Vec<u8> = con.get(key.clone()).unwrap();
            let mut res = bincode::deserialize(&bin);
            while res.is_err() {
                bin = con.get(key.clone()).unwrap();
                res = bincode::deserialize(&bin);
            }
            
            let s2data: TransactionPackage = res.unwrap();
            let cor_s = MulState::cor(&corshare1s, &(s2data.cshare_s));
            let cor_d = MulState::cor(&corshare1d, &(s2data.cshare_d));
            let outshare1s = state1s.out_share(&cor_s);
            let outshare1d = state1d.out_share(&cor_d);
            // ======================================================================================
            let mut encoded: Vec<u8> = Vec::new();
            encoded.extend(bincode::serialize(&(outshare1s.clone(), outshare1d.clone())).unwrap());
            let mut key: Vec<u8> = Vec::new();
            key.extend([1u8, 3u8]); // SERVER ID, TYPE
            key.extend(td.id.to_be_bytes());
            let _ : () = con.set(key.clone(), encoded).unwrap();
            // WAIT for response
            key[0] = 2u8;
            let mut bin: Vec<u8> = con.get(key.clone()).unwrap();
            let mut res = bincode::deserialize(&bin);
            while res.is_err() {
                bin = con.get(key.clone()).unwrap();
                res = bincode::deserialize(&bin);
            }
            let s2sketch: (OutShare<FieldElm>, OutShare<FieldElm>) = res.unwrap();
            MulState::verify(&outshare1s, &s2sketch.0);
            MulState::verify(&outshare1d, &s2sketch.0);
            // ======================================================================================
            // Verify triple proof!
            
            let g_r2_1: RistrettoPoint = g_r2.decompress().expect("REASON");
            let g_r2_2: RistrettoPoint = s2data.g_r2.decompress().expect("REASON");
            let g_r2 = g_r2_1 + g_r2_2;
            let g_r3_1: RistrettoPoint = g_r3.decompress().expect("REASON");
            let g_r3_2: RistrettoPoint = s2data.g_r3.decompress().expect("REASON");
            let g_r3 = g_r3_1 + g_r3_2;
            let comx_1: RistrettoPoint = com_x.decompress().expect("REASON");
            let comx_2: RistrettoPoint = s2data.com_x.decompress().expect("REASON");
            let comx = comx_1 + comx_2;
            let comix_1: RistrettoPoint = com_ix.decompress().expect("REASON");
            let comix_2: RistrettoPoint = s2data.com_ix.decompress().expect("REASON");
            let comix = comix_1 + comix_2;
            let g_r1 = td.g_r1.decompress().expect("REASON");
            let com_i = td.com_i.decompress().expect("REASON");
            let mut ver = true; // same_group_val_verify(&result[..].to_vec(), &(s2data.gp_val_ver));
            // let res = verify_coms_from_dpf(g_r1, g_r2, g_r3, com_i, comx, comix, td.triple_proof);
            // if res.is_err() {
            //     ver = false;
            //     println!("Triple Proof didn't verify!");
            // }
            let mut success = String::from("Transaction Processed");
            if ver != true {
                println!("Invalid!");
                success = String::from("Invalid Transaction");
            }
            else {
                // Proofs have been verified, now complete transaction
                let mut guard = database.lock().unwrap();
                ServerData::transact(guard.deref_mut(), &eval_all_src, &eval_all_dest);
            }
            let encoded = bincode::serialize(&success).unwrap();
            let _ = stream.write(&encoded);
        }
        // TYPE: SETTLING
        // DATA: Settle Request
        if buf[0] == 5 {
            let bytes_read = 176;
            let mut buf1 = [0;176];
            stream.read_exact(&mut buf1)?;
            let settle_data: SettleData = bincode::deserialize(&buf1[0..bytes_read]).unwrap();
            // ENCRYPT THE DATABASE, SEND TO S2
            let guard = database.lock().unwrap();
            let key_guard = prf_keys.lock().unwrap();
            let enc_db1 = ServerData::encrypt_db(guard.deref(), key_guard.deref(), settle_data.r_seed);
            drop(guard);
            // NOW PUBLISH ENCRYPTED DATABASE VECTOR
            let encoded = bincode::serialize(&enc_db1).unwrap();
            // println!("{:?}", encoded.len());
            let mut key: Vec<u8> = Vec::new();
            key.extend([1u8, 4u8]); // SERVER ID, TYPE
            let _ : () = con.set(key.clone(), encoded).unwrap();
            // AWAIT ENCRYPTED DATABASE VECTOR FROM S2
            key[0] = 2u8;
            let mut bin: Vec<u8> = con.get(key.clone()).unwrap();
            let mut res = bincode::deserialize(&bin);
            while res.is_err() {
                bin = con.get(key.clone()).unwrap();
                res = bincode::deserialize(&bin);
            }
            
            let s2enc_db: Vec<FieldElm> = res.unwrap();
            let balance_vec1 = ServerData::settle(&enc_db1, &s2enc_db, &settle_data.dpf_key);
            let encoded = bincode::serialize(&balance_vec1).unwrap();
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

    let receiver_listener = TcpListener::bind("0.0.0.0:7878").expect("Failed and bind with the sender");
    let mut thread_vec: Vec<thread::JoinHandle<()>> = Vec::new();

    // Initialize Server Data
    let issuer = Issuer::new(5);
    let mut vec_db = Vec::<FieldElm>::new();
    for _i in 0..MAX_GROUP_SIZE * MAX_GROUP_NUM {
        vec_db.push(FieldElm::zero());
    }
    let mut vec_keys = Vec::<Vec<u8>>::new();
    let zbytes = [0u8; 16];
    for _i in 0..MAX_GROUP_NUM {
        vec_keys.push(zbytes.to_vec());
    }
    let database = Arc::new(Mutex::new(vec_db));
    let prf_keys = Arc::new(Mutex::new(vec_keys));
    let counter = Arc::new(Mutex::new(0usize));

    type HmacSha256 = Hmac<Sha256>;
    let random_bytes = thread_rng().gen::<[u8; 32]>();
    let mac = HmacSha256::new_varkey(&random_bytes).expect("HMAC can take key of any size");

    let mut streams = 0;
    for stream in receiver_listener.incoming() {
        let stream = stream.expect("failed");
        let counter = counter.clone();
        let database = database.clone();
        let prf_keys = prf_keys.clone();
        let my_issuer = issuer.clone();
        let my_mac = mac.clone();
        streams += 1;
        let handle = thread::spawn(move || {
            handle_client(stream, my_issuer, counter, database, prf_keys, &my_mac, &streams).unwrap_or_else(|error| eprintln!("{:?}",error))
        });
        thread_vec.push(handle);
    }

    for handle in thread_vec {
        handle.join().unwrap();
    }
    Ok(())
}
