//
// Copyright 2019 Tamas Blummer
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
//!
//! # Connector to downstream modules
//!

use bitcoin::{
    blockdata::{
        block::{Block, BlockHeader}
    },
};

use std::sync::{Arc, Mutex};

pub type SharedDownstream = Arc<Mutex<dyn Downstream>>;

pub trait Downstream : Send + Sync {
    /// called by the node if new block added to trunk (longest chain)
    fn block_connected(&mut self, block: &Block, height: u32);

    /// called by the node if new header added to trunk (longest chain)
    fn header_connected(&mut self, header: &BlockHeader, height: u32);

    /// called by the node if a block is removed from trunk (orphaned from longest chain)
    fn block_disconnected(&mut self, header: &BlockHeader);
}

pub struct DownStreamDummy {}

impl Downstream for DownStreamDummy {
    fn block_connected(&mut self, _block: &Block, _height: u32) {}

    fn header_connected(&mut self, _header: &BlockHeader, _height: u32) {}

    fn block_disconnected(&mut self, _header: &BlockHeader) {}
}