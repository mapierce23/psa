# psa 

Code that accompanies the "Silent Splitter: Privacy for Payment Splitting via
New Protocols for Distributed Point Functions" paper. Utilizes publicly available code for Keyed-Verification Anonymous Credentials (by Ian Goldberg) and Distributed Point Functions (by Henry Corrigan-Gibbs). 

This requires the nightly version of Rust. Install Rust: https://www.rust-lang.org/tools/install then set the default version to 'nightly' by running: 

rustup install nightly
rustup default nightly

To run locally: you must run a local Redis server. Install Redis here: https://redis.io/downloads/. Ensure that the redis port # in server1.rs and server2.rs is correct. 

First, from the PaymentSplittingApp directory, compile and run servers S1 and S2: 

cargo run --bin server1

cargo run --bin server2

Also ensure that the port #s for SERVER1 and SERVER2 are correct in clients.rs. Then run the client:

cargo run --bin clients

You can adjust the number of groups, clients, and transactions in a given trial by editing the main() function of clients.rs. 

This material is based upon work supported by the National Science Foundation under Grant No. 2234408. Any opinions, findings, and conclusions or recommendations expressed in this material are those of the author(s) and do not necessarily reflect the views of the National Science Foundation.
