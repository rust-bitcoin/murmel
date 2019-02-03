# Murmel
Murmel is a lightweight Bitcoin node. Its intended use is to serve a lightning network stack with a settlement layer.
Its resource requirements are marginal if compared to a Bitcoin Core node.

Murmel filters blocks on client side implementing [BIP157](https://github.com/bitcoin/bips/blob/master/bip-0157.mediawiki).
Since Bitcoin Core does not yet support BIP157, Murmel may also be operated as filter server to serve a 
lightweight instance of itself.

A Murmel determines the chain with most work on its own and is capable of doing further checks. Its
security guarantee is at least as defined in the Simplified Payment Verification (SPV) section of Satoshi's white paper.

Murmel does not maintain a memory pool of transactions, as payments are assumed to use the Lightning Network layer 
therefore only confirmed transactions, those opening and closing channels on the blockchain, are of interest here.

#### About the name
Murmel is German for marble. Murmel is small, fast, hard and beautiful just like a marble. 

## Design and Implementation notes
Murmel implements a small and fast P2P engine using on [mio](https://crates.io/crates/mio). The network messages are routed 
to their respective processors and back through message queues. Processors of logically distinct tasks are otherwise 
de-coupled and run in their own thread. Murmel is written entirely in safe Rust, no unsafes not even RefCell's.

The blockchain data is persisted in a [Hammersbald](https://github.com/rust-bitcoin/hammersbald) database. 
The calculated [BIP157](https://github.com/bitcoin/bips/blob/master/bip-0157.mediawiki) filters for scripts and also for
spent outpoints allow checking the UTXO based on its immutable store. In contrast to Bitcoin Core, Murmel filter server 
does not have to re-compute anything on a re-org (switch of fork with most work).

## Status
Not yet for serious use. Murmel is able to support it's own and [rust-lightning](https://github.com/rust-bitcoin/rust-lightning) development. 

## How to run a filter server
Murmel supports client development as a BIP157 filter server. For this it needs to build up a complete Bitcoin blockchain
and compute filters. Run the server as follows:

```$xslt
cargo build --release
target/release/server --utxo-cache 65 
```

Execute server with --help option to get further hints. It is recommended to point with --peer to a bitcoin node 
that will answer quickly. Bootstrap will use about 12GB of memory for the UTXO cache and finish within 6 hours, building
a 210 GiB [Hammersbald]((https://github.com/rust-bitcoin/hammersbald)) database of the Bitcoin blockchain and filters
(block height: 562316).

A lower cache setting is not recommended for bootstrap as finding spent coins via filters is magnitudes slower, but 
fast enough to keep up with the chain once bootstrapped. Cache is not needed after bootstrap, the memory requirement 
is 0.7 GB without cache.

## How to run Murmel
Murmel does not do anything useful yet, but demonstrates how it would load block headers and filtered blocks.
```
cargo buld --release
target/release/client
```
Above assumes that a filter server is running locally. Murmel will download block and filter headers within 
6 Minutes and build a [Hammersbald]((https://github.com/rust-bitcoin/hammersbald)) dabase of 250MB. Its memory 
footprint is around 400MB

## Uses
Murmel uses and supports below projects:

* [Rust language bindings for Bitcoin secp256k1 library.](https://github.com/rust-bitcoin/rust-secp256k1)
* [Rust Bitcoin library](https://github.com/rust-bitcoin/rust-bitcoin)
* [Bitcoin's libbitcoinconsenus.a with Rust binding.](https://github.com/rust-bitcoin/rust-bitcoinconsensus)
* [Rust-Lightning, not Rusty's Lightning](https://github.com/rust-bitcoin/rust-lightning)
* [Hammersbald](https://github.com/rust-bitcoin/hammersbald)

