//! Asynchronous DNS resolver

use std::{
    io::{self, ErrorKind},
    net::SocketAddr,
};
use std::future::Future;
use std::pin::Pin;

use futures::{compat::Future01CompatExt, FutureExt};
use futures01::Future as Future01;
use trust_dns_resolver::{AsyncResolver, config::ResolverConfig};

use crate::temp::context::SharedContext;

pub fn create_resolver(dns: Option<ResolverConfig>) -> AsyncResolver {
    let (resolver, bg) = {
        // To make this independent, if targeting macOS, BSD, Linux, or Windows, we can use the system's configuration:
        #[cfg(any(unix, windows))]
            {
                if let Some(conf) = dns {
                    use trust_dns_resolver::config::ResolverOpts;
                    AsyncResolver::new(conf, ResolverOpts::default())
                } else {
                    use trust_dns_resolver::system_conf::read_system_conf;
                    // use the system resolver configuration
                    let (config, opts) = read_system_conf().expect("Failed to read global dns sysconf");
                    AsyncResolver::new(config, opts)
                }
            }

        // For other operating systems, we can use one of the preconfigured definitions
        #[cfg(not(any(unix, windows)))]
            {
                // Directly reference the config types
                use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};

                if let Some(conf) = dns {
                    AsyncResolver::new(conf, ResolverOpts::default())
                } else {
                    // Get a new resolver with the google nameservers as the upstream recursive resolvers
                    AsyncResolver::new(ResolverConfig::google(), ResolverOpts::default())
                }
            }
    };

    // NOTE: resolving will always be called inside a future.
    tokio::spawn(Box::new(bg).compat().map(|_|()));

    resolver
}


impl SharedContext {
    pub async fn resolve(&self,
        addr: &str,
        port: u16,
        check_forbidden: bool,
    ) -> io::Result<Vec<SocketAddr>> {
        self.inner_resolve(addr, port, check_forbidden).await
    }

    async fn inner_resolve(&self,
        addr: &str,
        port: u16,
        check_forbidden: bool,
    ) -> io::Result<Vec<SocketAddr>> {
        // let owned_addr = addr.to_owned();
        match self.get_context().dns_resolver().lookup_ip(addr).compat().await {
            Err(err) => {
                // error!("Failed to resolve {}, err: {}", owned_addr, err);
                Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("dns resolve error: {}", err),
                ))
            }
            Ok(lookup_result) => {
                let mut vaddr = Vec::new();
//            for ip in lookup_result.iter() {
//                if check_forbidden {
//                    let forbidden_ip = context.config().forbidden_ip;
//                    if forbidden_ip.contains(&ip) {
//                        // debug!("Resolved {} => {}, which is skipped by forbidden_ip", owned_addr, ip);
//                        continue;
//                    }
//                }
//                vaddr.push(SocketAddr::new(ip, port));
//            }

                if vaddr.is_empty() {
                    let err = io::Error::new(
                        ErrorKind::Other,
                        // format!("resolved {} to empty address, all IPs are filtered", owned_addr),
                        "resolved to empty address, all IPs are filtered",
                    );
                    Err(err)
                } else {
                    // debug!("Resolved {} => {:?}", owned_addr, vaddr);
                    Ok(vaddr)
                }
            }
        }
    }
}

