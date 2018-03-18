use bitcoin::network::constants::Network;
use database::DB;
use dispatcher::Dispatcher;
use error::SPVError;
use lightning::chain::chaininterface::ChainWatchInterface;
use node::Node;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use tokio::executor::current_thread;
use lighningconnector::LightningConnector;

pub struct SPV{
    connector: Arc<LightningConnector>
}

impl SPV {
    // Initialize the SPV stack and return a ChainWatchInterface
    // Set
    //      network - main or testnet
    //      bootstrap - peer adresses (only tested to work with one local node for now)
    //      db - file path to store the headers and blocks database
    // The method will read previously stored headers from the database and sync up with the peers
    // then serve the returned ChainWatchInterface
    pub fn new(network: Network, peers: Vec<SocketAddr>, db: &Path) -> Result<SPV, SPVError> {
        let mut db = DB::new(db)?;
        create_tables(&mut db)?;
        let node = Arc::new(Node::new(network, db));
        node.load_headers()?;
        let dispatcher = Dispatcher::new(network, 0);
        let cnode = node.clone();
        current_thread::run (|_| {
            current_thread::spawn(dispatcher.run(node, peers))
        });
        Ok(SPV{ connector: cnode.get_chain_watch_interface () })
    }

    pub fn get_chain_watch_interface (&self) -> Arc<ChainWatchInterface> {
        return self.connector.clone();
    }
}

fn create_tables(db: &mut DB) -> Result<(), SPVError> {
    let tx = db.transaction()?;
    tx.create_tables()?;
    tx.commit()?;
    Ok(())
}