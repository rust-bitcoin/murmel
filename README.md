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
Under refactoring.

## How to run Murmel
Murmel does not do anything useful yet.

