extern crate tempfile;
extern crate bitcoin;
extern crate murmel;
extern crate simple_logger;
extern crate log;

use std::io;
use std::str;
use std::fs::File;
use std::io::Write;
use std::process::{Command, Stdio};
use std::{thread, time};

use bitcoin::network::constants::Network;
use murmel::constructor::Constructor;
use log::Level;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};


struct Bitcoind {
    datadir: tempfile::TempDir,
    config_path: String
}

impl Drop for Bitcoind {
    fn drop(&mut self) {
        self.cli(&["stop"]).unwrap();
        thread::sleep(time::Duration::from_secs(1));
    }
}

fn bitcoind() -> Result<Bitcoind, io::Error> {
    let datadir = tempfile::TempDir::new()?;
    let config = datadir.path().join("bitcoin.conf");
    let config_path = config.clone().to_str().unwrap().to_owned();
    let mut config_file = File::create(config)?;
    writeln!(config_file, "rpcuser=regtest")?;
    writeln!(config_file, "rpcpassword=regtest")?;
    writeln!(config_file, "port=28333")?;


    println!("starting bitcoind with -conf={}", config_path);
    let _bitcoind = Command::new("bitcoind")
        .arg("-regtest")
        .arg("-daemon")
        .arg(format!("-conf={}", config_path))
        .arg(format!("-datadir={}", datadir.path().to_str().unwrap()))
        .stdout(Stdio::piped())
        .spawn()?;

    thread::sleep(time::Duration::from_secs(2));
    Ok(Bitcoind{datadir, config_path})
}

impl Bitcoind {
    fn cli(&self, args: &[&str]) -> Result<String, io::Error> {
        println!("starting bitcoin-cli {}", args.iter()
            .map(|s| {let mut str = s.to_string(); str.push_str(" "); str})
            .collect::<Vec<_>>().concat());
        let bitcoind = Command::new("bitcoin-cli")
            .arg("-regtest")
            .arg(format!("-conf={}", self.config_path))
            .arg(format!("-datadir={}", self.datadir.path().to_str().unwrap()))
            .arg("-rpcuser=regtest")
            .arg("-rpcpassword=regtest")
            .args(args)
            .stdout(Stdio::piped())
            .spawn()?;

        let output = bitcoind.wait_with_output()?;

        Ok(str::from_utf8(output.stdout.as_slice()).unwrap().to_string())
    }
}

#[test]
fn download() {
    let bitcoind = bitcoind().unwrap();
    bitcoind.cli(&["generate", "500"]).unwrap();
    thread::sleep(time::Duration::from_secs(2));
    simple_logger::init_with_level(Level::Trace).unwrap();
    let mut peers = Vec::new();
    peers.push(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 28333));
    thread::spawn(|| {
        let mut spv = Constructor::new_in_memory("/rust-spv:0.1.0/".to_string(), Network::Regtest, vec!(), false, 0, 0).unwrap();
        spv.run(peers, 1, true).unwrap();
    });
    thread::sleep(time::Duration::from_secs(5));
}