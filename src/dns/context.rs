//! The `ServerContext in this thread holds the common state across the server

use std::io::Result;
use std::sync::Arc;
use std::path::Path;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use dns::resolve::{DnsResolver,RecursiveDnsResolver,ForwardingDnsResolver};
use dns::client::{DnsClient,DnsNetworkClient};
use dns::cache::SynchronizedCache;
use dns::authority::Authority;
use dns::filter::DnsFilter;
use dns::utils::current_time_millis;

pub struct ServerStatistics {
    start_time: u64,
    tcp_query_count: u64,
    udp_query_count: u64,
    min_request_time: u64,
    max_request_time: u64,
    avg_request_time: u64
}

impl ServerStatistics {
    pub fn new() -> ServerStatistics {
        ServerStatistics {
            start_time: current_time_millis(),
            tcp_query_count: 0u64,
            udp_query_count: 0u64,
            min_request_time: 0u64,
            max_request_time: 0u64,
            avg_request_time: 0u64,
        }
    }

    pub fn get_tcp_query_count(&self) -> u64 {
        self.tcp_query_count
    }

    pub fn get_udp_query_count(&self) -> u64 {
        self.udp_query_count
    }

    pub fn add_request_time(&mut self, request_time: u64, udp: bool) {
        if request_time > self.max_request_time {
            self.max_request_time = request_time;
        }
        if self.min_request_time == 0 {
            self.min_request_time = request_time;
        }
        if request_time > 0 && request_time < self.min_request_time {
            self.min_request_time = request_time;
        }
        let query_count = self.udp_query_count + self.tcp_query_count;

        self.avg_request_time = (self.avg_request_time * (query_count) + request_time) / (query_count + 1);

        if udp {
            self.udp_query_count += 1;
        } else {
            self.tcp_query_count += 1;
        }
    }

    #[allow(dead_code)]
    pub fn print(&self) {
        println!("Statistics from time: {}\nUDP requests: {}\nTCP requests: {}\nMin time: {}\nMax time: {}\nAvg time: {}\n",
                self.start_time, self.udp_query_count, self.tcp_query_count, self.min_request_time, self.max_request_time, self.avg_request_time);
    }
}

pub enum ResolveStrategy {
    Recursive,
    Forward {
        host: String,
        port: u16
    }
}

pub struct ServerContext {
    pub authority: Authority,
    pub cache: SynchronizedCache,
    pub client: Box<DnsClient + Sync + Send>,
    pub dns_bind_ip: String,
    pub dns_port: u16,
    pub api_port: u16,
    pub resolve_strategy: ResolveStrategy,
    pub allow_recursive: bool,
    pub threads_udp: u32,
    pub threads_tcp: u32,
    pub enable_api: bool,
    pub filter: DnsFilter,
    pub statistics: Mutex<ServerStatistics>
}

impl Default for ServerContext {
    fn default() -> Self {
        ServerContext::new()
    }
}

impl ServerContext {
    pub fn new() -> ServerContext {
        ServerContext {
            authority: Authority::new(),
            cache: SynchronizedCache::new(),
            client: Box::new(DnsNetworkClient::new(34555)),
            dns_bind_ip: "0.0.0.0".to_owned(),
            dns_port: 53,
            api_port: 5380,
            resolve_strategy: ResolveStrategy::Recursive,
            allow_recursive: true,
            threads_udp: 32,
            threads_tcp: 32,
            enable_api: true,
            filter: DnsFilter::new(),
            statistics: Mutex::new(ServerStatistics::new())
        }
    }

    pub fn initialize(&mut self) -> Result<()> {
        // Load filter rules
        self.filter.load_rules(Path::new("filter.txt"));

        // Start UDP client thread
        try!(self.client.run());

        // Load authority data
        try!(self.authority.load());

        Ok(())
    }

    pub fn create_resolver(&self, ptr: Arc<ServerContext>) -> Box<DnsResolver> {
        match self.resolve_strategy {
            ResolveStrategy::Recursive => Box::new(RecursiveDnsResolver::new(ptr)),
            ResolveStrategy::Forward { ref host, port } => {
                Box::new(ForwardingDnsResolver::new(ptr, (host.clone(), port)))
            }
        }
    }
}

#[cfg(test)]
pub mod tests {

    use std::sync::Arc;
    use std::sync::atomic::AtomicUsize;

    use dns::authority::Authority;
    use dns::cache::SynchronizedCache;

    use dns::client::tests::{StubCallback,DnsStubClient};

    use super::*;

    pub fn create_test_context(callback: Box<StubCallback>) -> Arc<ServerContext> {

        Arc::new(ServerContext {
            authority: Authority::new(),
            cache: SynchronizedCache::new(),
            client: Box::new(DnsStubClient::new(callback)),
            dns_port: 53,
            api_port: 5380,
            resolve_strategy: ResolveStrategy::Recursive,
            allow_recursive: true,
            threads_udp: 32,
            threads_tcp: 32,
            enable_api: true,
            filter: DnsFilter::new(),
            statistics: Mutex::new(ServerStatistics::new())
        })

    }

}
