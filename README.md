# Bitcoin SPV in Rust
This is an implementation of Bitcoin's Simplified Payment Verification mode. The SPV mode is suitable for lightweight nodes, such as a mobile phone. An SPV node verifies proof-of-work of a block but does not validate included transactions. It will follow the chain with most work.

An SPV node needs to connect full nodes to work. It does not offer any services to other nodes.

This implementation is taylored to serve a Lightning Network node on a resource and bandwidth limited device. It does not feature a memory pool of transactions, as payments are assumed to use the Lightning layer and otherwise only confirmed transactions are of interest.

## Status
This is work in progess, far from production quality. It aims to serve parallel development of a Lightning Node.

The code currently has a lot of dependencies as I wanted to make progess quickly towards the stuff that is really new. Most dependencies will be removed later.  Networking and Database code is carefully isolated from the logic of the node, so their implementations can be replaced.

I plan to implement BIP157 and BIP158 as soon as they are available in Bitcoin. Until that the node will download full blocks. I do not want to waste time implementing BIP37 that hurts privacy.

## Contributions and Vision
The current plan is to create a small footprint, low bandwidth, stable and secure Lightning Network node combining with the below projects:

* [Rust language bindings for Bitcoin secp256k1 library.](https://github.com/rust-bitcoin/rust-secp256k1)
* [Rust Bitcoin library](https://github.com/rust-bitcoin/rust-bitcoin)
* [Bitcoin's libbitcoinconsenus.a with Rust binding.](https://github.com/rust-bitcoin/rust-bitcoinconsensus)
* [Bitcoin SPV in Rust](https://github.com/rust-bitcoin/bitcoin-spv)
* [Rust-Lightning, not Rusty's Lightning](https://github.com/rust-bitcoin/rust-lightning)

Send in your PRs if aligned with above vision.
