//! code copy from [shadowsocks-rust](https://github.com/shadowsocks/shadowsocks-rust)
//! Shadowsocks Server Context

use std::{
    io::{Error, ErrorKind, Result as IoResult},
    net::SocketAddr,
    sync::Arc,
    time::Instant,
};

use futures::lock::{Mutex, MutexLockFuture};
use lru_cache::LruCache;
use trust_dns_resolver::AsyncResolver;

use crate::temp::{config::Config, dns_resolver::create_resolver, socket5::Address};

type DnsQueryCache = LruCache<u16, (SocketAddr, Instant)>;

#[derive(Clone)]
pub struct Context {
    config: Config,
    dns_resolver: Arc<AsyncResolver>,
    dns_query_cache: Option<Arc<Mutex<DnsQueryCache>>>,
}

pub struct SharedContext(Arc<Context>);

impl SharedContext {
    pub(crate) fn new(context: Arc<Context>) -> Self {
        SharedContext(context)
    }

    pub(crate) fn get_context(&self) -> Arc<Context> {
        self.0.clone()
    }

    pub(crate) fn get_self(&self) -> Self {
        SharedContext(self.get_context())
    }

    pub(crate) async fn resolve_remote_addr(&self, addr: &Address) -> IoResult<SocketAddr> {
        match *addr {
            // Return directly if it is a SocketAddr
            Address::SocketAddress(ref addr) => Ok(*addr),
            // Resolve domain name to SocketAddr
            Address::DomainNameAddress(ref dname, port) => {
                let mut vec_ipaddr = self.resolve(dname, port, false).await?;
                vec_ipaddr.pop().ok_or_else(|| {
                    Error::new(
                        ErrorKind::AddrNotAvailable,
                        "Can't get socket addr from input Address",
                    )
                })
            }
        }
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
