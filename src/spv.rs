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
use tokio_core::reactor::Core;

pub struct SPV;

impl SPV {
    // Initialize the SPV stack and return a ChainWatchInterface
    // Set
    //      network - main or testnet
    //      bootstrap - peer adresses (only tested to work with one local node for now)
    //      db - file path to store the headers and blocks database
    // The method will read previously stored headers from the database and sync up with the peers
    // then serve the returned ChainWatchInterface
    pub fn new(network: Network, peers: Vec<SocketAddr>, db: &Path) -> Result<Arc<ChainWatchInterface>, SPVError> {
        let mut db = DB::new(Path::new("/tmp/blocks.sqlite"))?;
        create_tables(&mut db)?;
        let node = Rc::new(Node::new(Network::Bitcoin, db));
        node.load_headers()?;

        let dispatcher = Dispatcher::new(node.clone());

        let mut core = Core::new()?;
        let handle = core.handle();
        core.run(dispatcher.run(handle, &peers))?;
        Ok(node.get_chain_watch_interface())
    }
}

fn create_tables(db: &mut DB) -> Result<(), SPVError> {
    let tx = db.transaction()?;
    tx.create_tables()?;
    tx.commit()?;
    Ok(())
}