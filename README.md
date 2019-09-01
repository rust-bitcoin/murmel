[![Safety Dance](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/)

# Murmel
Murmel is a lightweight Bitcoin node. Its intended use is to serve a lightning network stack with a settlement layer.
Its resource requirements are marginal if compared to a Bitcoin Core node.

A Murmel determines the chain with most work on its own and is capable of doing further checks. Its
security guarantee is at least as defined in the Simplified Payment Verification (SPV) section of Satoshi's white paper.

The bitcoin network is governed by full nodes. Full nodes determine which blocks are valid and thereby decide if a miner gets paid
for the block it creates. The chain with most work therefore communicates what full nodes think bitcoin is. Therefore following
the chain with most work is not following miner, as in popular belief, but following the majority opinion of full nodes.
Read more about this [here](https://medium.com/@tamas.blummer/follow-the-pow-d6d1d1f479bd).

Murmel does not maintain a memory pool of transactions, as unconfirmed payments unsecure to accept. 
Use Murmel to accept confirmed payments or to underpin a Ligthning Network node.

#### About the name
Murmel is German for marble. Murmel is small, fast, hard and beautiful just like a marble. 

## Design and Implementation notes
Murmel implements a small and fast P2P engine using on [mio](https://crates.io/crates/mio). The network messages are routed 
to their respective processors and back through message queues. Processors of logically distinct tasks are otherwise 
de-coupled and run in their own thread.

The blockchain data is persisted in a [Hammersbald](https://github.com/rust-bitcoin/hammersbald) database. 

Murmel's filter implementation [BIP158](https://github.com/bitcoin/bips/blob/master/bip-0158.mediawiki) was moved into the rust-bitcoin project,
[here](https://github.com/rust-bitcoin/rust-bitcoin/blob/master/src/util/bip158.rs).

Murmel will not use those filters until they are available committed into the bitcoin block chain as they are otherwise not safe to use:
a disagreement between two sources of filters can not be resolved by a client without knowledge of the UTXO. Consulting a third node would evtl. give yet another answer. 

Filters that could be verified with the block content alone, as I (repeatedly) suggested on the 
[dev-list](https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2019-February/016646.html), 
were rejected in favor of the current design, that is in fact more convenient once committed, but only then.


## Status
Under refactoring.

## How to run Murmel
Murmel does not do anything useful yet.

