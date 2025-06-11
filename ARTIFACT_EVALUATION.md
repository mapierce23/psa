# Artifact Appendix

Paper title:  Silent Splitter: Privacy for Payment Splitting via New Protocols for Distributed Point Functions 

Artifacts HotCRP Id: **#Enter your HotCRP Id here** (not your paper Id, but the artifacts id)

Requested Badge: **Functional**

## Description
The source code mentioned in section 6 of our paper, "Implementation and Evaluation." An implementation of our payment system, with clients and two servers. 

### Security/Privacy Issues and Ethical Concerns (All badges)
Not applicable. When open source code not authored by us is utilized, it is credited in the README. 

## Basic Requirements (Only for Functional and Reproduced badges)
This can be run on a laptop, but will likely produce slower results than listed in the paper. We evaluated it with 2 Google Cloud compute instances simulating the two servers, with 32vCPUs, 16 cores, and 128GB memory each. 
A laptop can easily play the role of the clients, given that that is more likely what would happen in the real world. 

### Hardware Requirements
No specific hardware required. 

### Software Requirements
No specific software required. 

### Estimated Time and Storage Consumption
< 1 Hour and minimal storage to determine the functionality of the artifact. To re-run all experiments to obtain the data listed in the paper, likely 3-4 hours. 

## Environment 
See the README for instructions on how to run the artifact. The only software necessary to install should be Redis open source (https://redis.io/downloads/) and a Rust compiler, if one is not already installed. 

### Accessibility (All badges)
The code is in this Git repository, https://github.com/mapierce23/psa. The latest commit hash is 51914cb1e468b68bdc6038c7b0bbc4471bda7a16, which is the one that should be evaluated. 

### Set up the environment (Only for Functional and Reproduced badges)
If you use multiple machines or VM instances to run the two servers and clients, you'll need to clone this git repo on each one. 

```bash
git clone https://github.com/mapierce23/psa.git
```

You'll also need to install Redis open source (https://redis.io/downloads/) and run a Redis server before performing any trials. Start the redis server using:

```bash
redis-server
```

Determine the ip address of the redis server with:

```bash
ipconfig
```

Update the REDIS constant in server1.rs and server2.rs with this info, for example:

```bash
pub const REDIS: &str = "redis://10.128.0.4:6379";
```

You will also need to update clients.rs with the ip addresses of the servers (see constants SERVER1 and SERVER2) before things will run properly. 

### Testing the Environment (Only for Functional and Reproduced badges)
To ensure that things are set up correctly, simply run the two servers and clients simultaneously as specified in the README. The print statements specifying "Thruput" and "Latency" will show if everything has been set up correctly. 

## Artifact Evaluation (Only for Functional and Reproduced badges)

### Main Results and Claims

#### Transaction Throughput and Latency
Our claim is that transaction throughput and latency is primarily limited by the DPF baseline. In other words, DPF evaluation accounts for the majority of the computation, 
and our system adds very little overhead on top of that. For specific numbers see Figures 7 and 8 in the paper. 

#### Balance Retrieval Latency
Our claim is that balance retrieval latency is primarily limited by the time it takes for the servers to produce an encrypted database. In other words, this encryption accounts for the 
majority of the computation, and since one computation of the database can be reused for many user queries, balance retrieval is generally quite fast. See figure 9 in the paper. 

### Experiments 
For each experiment, the code will be run as outlined in the README. The only modifications will need to be made to the constants located in lib.rs, such as MAX_GROUP_SIZE and MAX_GROUP_NUM. This represents the 
size of each group and the number of groups total, respectively. 

#### Experiment 1: Transactions
For transactions, the size of the database is the limiting factor. Set MAX_GROUP_SIZE to 10, and vary MAX_GROUP_NUM from 100 to 10000, multiplying
by 10 each time. The database size is MAX_GROUP_SIZE * MAX_GROUP_NUM, so it will vary from 1000 to 100,000.
For each group num, run the code and view the resulting Thruput and Latency. 
#### Experiment 2: Balance Retrieval
As in Experiment 1, the size of the database is the limiting factor and the number of groups has minimal impact. With that in mind, set MAX_GROUP_SIZE to 10, 
and vary MAX_GROUP_NUM from 100 to 10000, multiplying by 10 each time. The database size is MAX_GROUP_SIZE * MAX_GROUP_NUM, so it will vary from 1000 to 100,000.
Uncomment lines 413-414 in clients.rs to measure Balance Retrieval Latency rather than transaction throughput. Observe how the latency increases with database size. 


## Limitations (Only for Functional and Reproduced badges)
Not included here are the tables we provided regarding communication costs, since they are easily calculated. We also do not outline a way to verify proof verification time,
since this is essentially constant regardless of database size. 

## Notes on Reusability (Only for Functional and Reproduced badges)
This may be used as a starting point/framework for eventually implementing Silent Splitter in the real world. The cryptography and proof functionalities are all implemented in Rust, and are usable as they are. 
