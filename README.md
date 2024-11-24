# psa 

Code that accompanies the "Silent Splitter: Privacy for Payment Splitting via
New Protocols for Distributed Point Functions" paper. Utilizes publicly available code for Keyed-Verification Anonymous Credentials (by Ian Goldberg) and Distributed Point Functions (by Henry Corrigan-Gibbs). 

To run locally: you must run a local Redis server. Also ensure that the port #s for SERVER1 and SERVER2 are correct in clients.rs. Then run server1.rs, server2.rs, and clients.rs simultaneously. 
