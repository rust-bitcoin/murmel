use bitcoin::blockdata::block::{Block, BlockHeader};
use bitcoin::blockdata::script::Script;
use bitcoin::util::hash::Sha256dHash;
use lightning::chain::chaininterface::{ChainListener,ChainWatchInterface, ChainWatchInterfaceUtil};
use node::Broadcaster;
use std::sync::Weak;

pub struct LightningConnector {
    util: ChainWatchInterfaceUtil,
    broadcaster: Broadcaster
}

impl LightningConnector {
    pub fn new (broadcaster: Broadcaster) -> LightningConnector {
        LightningConnector {
            util: ChainWatchInterfaceUtil::new(),
            broadcaster
        }
    }

    pub fn block_connected(&self, block: &Block, height: u32) {
        self.util.block_connected(block, height)
    }

    pub fn block_disconnected(&self, header: &BlockHeader) {
        self.util.block_disconnected(header)
    }
}

impl ChainWatchInterface for LightningConnector {
    fn install_watch_script(&self, script_pub_key: Script) {
        self.util.install_watch_script(script_pub_key)
    }

    fn install_watch_outpoint(&self, outpoint: (Sha256dHash, u32)) {
        self.util.install_watch_outpoint(outpoint)
    }

    fn watch_all_txn(&self) {
        self.util.watch_all_txn()
    }

    fn register_listener(&self, listener: Weak<ChainListener>) {
        self.util.register_listener(listener)
    }
}