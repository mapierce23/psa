#![allow(non_snake_case)]
use std::net::TcpStream;
use std::io::{self, Read, Write};

use payapp::ps::*;

fn main() -> io::Result<( )> {

    // let alpha_bits = u32_to_bits(5, 21);
    // let non_alpha_bits = u32_to_bits(5, 22);
    // let values = vec![FieldElm::one(); alpha_bits.len()-1];
    // let (key0, key1) = DPFKey::<FieldElm, FieldElm>::gen(&alpha_bits, &values, &FieldElm::one());
    // let encoded: Vec<u8> = bincode::serialize(&key0).unwrap();
    let mut leader = GpLeaderData::new(10);
    let mut stream = TcpStream::connect("127.0.0.1:7878")?;


    // GROUP SETUP
    let mut encoded: Vec<u8> = Vec::new();
    let prf_keys = (4u64, 5u64);
    encoded.push(1u8);
    encoded.extend(bincode::serialize(&prf_keys).unwrap());
    stream.write(&encoded).expect("failed to write");

    // Send group creation request to the server
    let mut buf = [0;8192];
    let mut bytes_read = 0;
    while bytes_read == 0 {
        bytes_read = stream.read(&mut buf)?;
    }

    // The server responds with a list of account IDs and a public key
    let (aids, pubkey) = bincode::deserialize(&buf[0..bytes_read]).unwrap();
    let creds = leader.group_setup(aids, stream, pubkey)?;
    println!("creds {:?}", creds.len());
    
    // }
    Ok(())
}

