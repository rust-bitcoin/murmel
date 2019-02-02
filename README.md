# Murmel
Murmel is a lightweight Bitcoin node. Its intended use is to serve a lightning network stack with a settlement layer.
Its resource requirements are marginal if compared to a Bitcoin Core node.

Murmel filters blocks on client side implementing [BIP157](https://github.com/bitcoin/bips/blob/master/bip-0157.mediawiki).
Since Bitcoin Core does not yet support BIP157, Murmel may also be operated as filter server to serve a 
lightweight instance of itself.

A Murmel client determines the chain with most work on its own and is capable of doing further checks. Its
security guarantee is at least as defined in the Simplified Payment Verification (SPV) section of Satoshi's white paper.

Murmel does not maintain a memory pool of transactions, as payments are assumed to use the Lightning Network layer and otherwise only confirmed transactions are of interest.

#### About the name
Murmel is German for marble. Murmel is small, fast, hard and beautiful just like a marble. 

## Design and Implementation notes
Murmel implements a small and fast P2P engine using on [mio](https://crates.io/crates/mio). The network messages are routed 
to their respective processors and back through message queues. Processors of logically distinct tasks are otherwise 
de-coupled and run in their own thread. 

The blockchain data is persisted in a [Hammersbald](https://github.com/rust-bitcoin/hammersbald) database. 
The calculated [BIP157](https://github.com/bitcoin/bips/blob/master/bip-0157.mediawiki) filters for scripts and also for
spent outpoints allow checking the UTXO based on its immutable store. In contrast to Bitcoin Core, Murmel does not have
to re-compute anything on a re-org (switch of fork with most work) and optionally able to verify spent coins and 
block reward. These additional checks to that required by SPV allows Murmel to have a security guarantee higher than
any other light node, but certainly still sub-par to a Bitcoin Core node.

## Status
Not yet for serious use. Murmel is able to support it's own and Lightning Node development. 

## How to run a filter server
Murmel supports client development as a BIP157 filter server. For this it needs to build up a complete Bitcoin blockchain
and compute filters. Run the server as follows:

```$xslt
cargo build --release
target/release/server --utxo-cache 75 
```
Execute server with --help option to get further hints. It is recommended to point with --peer to a bitcoin node 
that will answer quickly. Bootstrap will require about 12GB of RAM, for the UTXO cache and finish within hours. 
A lower cache setting is not recommended for bootstrap as finding UTXO via filters is magnitudes slower, but 
fast enough to keep up with the chain once bootstrapped. Cache is not needed after bootstrap, the RAM requirement 
is 0.7 GB without cache.


## Uses
Murmel uses and supports below projects:

* [Rust language bindings for Bitcoin secp256k1 library.](https://github.com/rust-bitcoin/rust-secp256k1)
* [Rust Bitcoin library](https://github.com/rust-bitcoin/rust-bitcoin)
* [Bitcoin's libbitcoinconsenus.a with Rust binding.](https://github.com/rust-bitcoin/rust-bitcoinconsensus)
* [Rust-Lightning, not Rusty's Lightning](https://github.com/rust-bitcoin/rust-lightning)
* [Hammersbald](https://github.com/rust-bitcoin/hammersbald)

