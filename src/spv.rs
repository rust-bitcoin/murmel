use bitcoin::network::constants::Network;
use database::DB;
use dispatcher::Dispatcher;
use error::SPVError;
use lightning::chain::chaininterface::ChainWatchInterface;
use node::Node;
use std::net::SocketAddr;
use std::path::Path;
use std::rc::Rc;
use std::sync::Arc;
use tokio::executor::current_thread;

pub struct SPV {
    node: Rc<Node>,
    dispatcher: Dispatcher
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
        let node = Rc::new(Node::new(network, db));
        let dispatcher = Dispatcher::new(node.clone(), peers);
        Ok(SPV{node, dispatcher})
    }

    pub fn get_chain_watch_interface (&self) -> Arc<ChainWatchInterface> {
        return self.node.get_chain_watch_interface()
    }

    pub fn run (&self) -> Result<(), SPVError> {
        self.node.load_headers()?;
        current_thread::run (|_| {
            current_thread::spawn(self.dispatcher.run())
        });
        Ok(())
    }
}

fn create_tables(db: &mut DB) -> Result<(), SPVError> {
    let tx = db.transaction()?;
    tx.create_tables()?;
    tx.commit()?;
    Ok(())
}