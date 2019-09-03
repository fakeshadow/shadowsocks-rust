//! Asynchronous DNS resolver

use std::{
    io::{self, Error, ErrorKind},
    net::SocketAddr,
};

use futures::{compat::Future01CompatExt, FutureExt};
use trust_dns_resolver::{config::ResolverConfig, AsyncResolver};

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
    // ToDo: remove compat layer when trust dns migrate to future0.3
    tokio::spawn(Box::new(bg).compat().map(|_| ()));

    resolver
}

impl SharedContext {
    pub async fn resolve(
        &self,
        addr: &str,
        port: u16,
        check_forbidden: bool,
    ) -> io::Result<Vec<SocketAddr>> {
        let lookup_result = self
            .get_context()
            .dns_resolver()
            .lookup_ip(addr)
            .compat()
            .await
            .map_err(|e| Error::new(ErrorKind::Other, format!("dns resolve error: {}", e)))?;

        let vaddr: Vec<SocketAddr> = if check_forbidden {
            let context = self.get_context();
            let forbidden_ip = &(context.config()).forbidden_ip;

            lookup_result
                .iter()
                .filter(|ip| !forbidden_ip.contains(ip))
                .map(|ip| SocketAddr::new(ip, port))
                .collect()
        } else {
            lookup_result
                .iter()
                .map(|ip| SocketAddr::new(ip, port))
                .collect()
        };

        if vaddr.is_empty() {
            let err = Error::new(
                ErrorKind::Other,
                "resolved to empty address, all IPs are filtered",
            );
            Err(err)
        } else {
            Ok(vaddr)
        }
    }
}
