//! code copy from [shadowsocks-rust](https://github.com/shadowsocks/shadowsocks-rust)
//! Shadowsocks Server Context

use std::{
    net::SocketAddr,
    sync::Arc,
    time::Instant,
};
use std::ops::Deref;

use futures::lock::{Mutex, MutexLockFuture};
use lru_cache::LruCache;
use trust_dns_resolver::AsyncResolver;

use crate::{temp::config::Config, temp::dns_resolver::create_resolver};

type DnsQueryCache = LruCache<u16, (SocketAddr, Instant)>;

#[derive(Clone)]
pub struct Context {
    config: Config,
    dns_resolver: Arc<AsyncResolver>,
    dns_query_cache: Option<Arc<Mutex<DnsQueryCache>>>,
}

pub struct SharedContext(Arc<Context>);

impl SharedContext {
    pub fn new(context: Arc<Context>) -> Self {
        SharedContext(context)
    }

    pub fn get_context(&self) -> Arc<Context> {
        self.0.clone()
    }

    pub fn get_self(&self) -> Self {
        SharedContext(self.get_context())
    }
}


impl Context {
    pub fn new(config: Config) -> Context {
        let resolver = create_resolver(config.get_dns_config());
        Context {
            config,
            dns_resolver: Arc::new(resolver),
            dns_query_cache: None,
        }
    }

    pub fn new_dns(config: Config) -> Context {
        let resolver = create_resolver(config.get_dns_config());
        Context {
            config,
            dns_resolver: Arc::new(resolver),
            dns_query_cache: Some(Arc::new(Mutex::new(LruCache::new(1024)))),
        }
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    pub fn config_mut(&mut self) -> &mut Config {
        &mut self.config
    }

    pub fn dns_resolver(&self) -> &AsyncResolver {
        &*self.dns_resolver
    }

    pub(crate) fn dns_query_cache(&self) -> MutexLockFuture<DnsQueryCache> {
        self.dns_query_cache.as_ref().unwrap().lock()
    }
}