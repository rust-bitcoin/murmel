//
// Copyright 2018 Tamas Blummer
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
//! # Tasks
//! a helper to use futures
//!

use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use futures::task::{Context, Waker};
use futures::{Future, Never,Async};
use futures::future;
use error::SPVError;
use futures::FutureExt;
use std::time::Duration;

pub struct Tasks {
    // waker to tasks
    waker: Arc<Mutex<HashMap<String, Waker>>>
}

impl Tasks {
    pub fn new () -> Tasks {
        Tasks {waker: Arc::new(Mutex::new(HashMap::new()))}
    }

    pub fn wake (&self, task_name: &str) {
        self.waker.lock().unwrap().get(&task_name.to_string()).unwrap().wake();
    }

    fn wrapper<F> (&self, task_name: &str, work: F) ->
        impl Future<Item=(), Error=SPVError>
        where F:Fn(&mut Context) -> Result<bool, SPVError> +Send +'static{
        let waker = self.waker.clone();
        let name = task_name.to_string();
        future::poll_fn (move | ctx| {
            waker.lock().unwrap().insert(name.clone(), ctx.waker().clone());
            match work(ctx) {
                Ok(ready) => {
                    if ready {
                        Ok(Async::Ready(()))
                    } else {
                        Ok(Async::Pending)
                    }
                }
                Err(e) => Err(e)
            }
        })
    }

    pub fn spawn<F,G> (&self, ctx: &mut Context, task_name: &str, work: F, fail: G)
        where F: Fn(&mut Context) -> Result<bool, SPVError> +Send+'static, G: Fn(SPVError) + Send+'static {
        let waker = self.waker.clone();
        let wrapper = Box::new(self.wrapper(task_name, work)
            .or_else(move |e:SPVError| -> Result<(), Never> {Ok(fail(e))}));
        ctx.spawn(wrapper);
    }

    pub fn spawn_no_error<F> (&self, ctx: &mut Context, task_name: &str, work: F)
        where F: Fn(&mut Context) -> Result<bool, SPVError> +Send+'static {
        let waker = self.waker.clone();
        let wrapper = Box::new(self.wrapper(task_name, work)
            .or_else(move |e:SPVError| -> Result<(), Never> {Ok(warn!("{}", e))}));
        ctx.spawn(wrapper);
    }

    pub fn spawn_with_timeout<F,G> (&self, ctx: &mut Context, task_name: &str, seconds: u32, work: F, fail: G)
        where F: Fn(&mut Context) -> Result<bool, SPVError> +Send+'static, G: Fn(SPVError) + Send+'static {
        use futures_timer::FutureExt;

        let waker = self.waker.clone();
        let wrapper = Box::new(self.wrapper(task_name, work).timeout(Duration::from_secs(seconds as u64))
            .or_else(move |e:SPVError| -> Result<(), Never> {Ok(fail(e))}));
        ctx.spawn(wrapper);
    }
}