//! resolver implementations implementing different strategies for answering incoming queries

use std::io::Result;
use std::vec::Vec;
use std::io::{Error, ErrorKind};
use std::sync::Arc;

use dns::protocol::{QueryType, DnsPacket, ResultCode};
use dns::context::ServerContext;
use dns::utils::current_thread_name;
use std::collections::HashSet;

pub trait DnsResolver {

    fn get_context(&self) -> Arc<ServerContext>;

    fn resolve(&mut self, qname: &str, qtype: QueryType, recursive: bool) -> Result<DnsPacket> {

        if let QueryType::UNKNOWN(_) = qtype {
            let mut packet = DnsPacket::new();
            packet.header.res_code = ResultCode::NOTIMP;
            return Ok(packet);
        }

        let context = self.get_context();

        if let Some(qr) = context.authority.query(qname, qtype) {
            return Ok(qr);
        }

        if !recursive || !context.allow_recursive {
            let mut packet = DnsPacket::new();
            packet.header.res_code = ResultCode::REFUSED;
            return Ok(packet);
        }

        if let Some(qr) = context.cache.lookup(qname, qtype) {
            return Ok(qr);
        }

        if qtype == QueryType::A || qtype == QueryType::AAAA {
            if let Some(qr) = context.cache.lookup(qname, QueryType::CNAME) {
                return Ok(qr);
            }
        }

        self.perform(qname, qtype)
    }

    fn perform(&mut self, qname: &str, qtype: QueryType) -> Result<DnsPacket>;
}

/// A Forwarding DNS Resolver
///
/// This resolver uses an external DNS server to service a query
pub struct ForwardingDnsResolver {
    context: Arc<ServerContext>,
    server: (String, u16)
}

impl ForwardingDnsResolver {
    pub fn new(context: Arc<ServerContext>, server: (String, u16)) -> ForwardingDnsResolver {
        ForwardingDnsResolver {
            context: context,
            server: server
        }
    }
}

impl DnsResolver for ForwardingDnsResolver {
    fn get_context(&self) -> Arc<ServerContext> {
        self.context.clone()
    }

    fn perform(&mut self, qname: &str, qtype: QueryType) -> Result<DnsPacket> {

        let &(ref host, port) = &self.server;
        let result = self.context.client.send_query(qname,
                                                    qtype,
                                                    (host.as_str(), port),
                                                    true);

        if let Ok(ref qr) = result {
            let _ = self.context.cache.store(&qr.answers);
        }

        result
    }
}

/// A Recursive DNS resolver
///
/// This resolver can answer any request using the root servers of the internet
pub struct RecursiveDnsResolver {
    context: Arc<ServerContext>
}

impl RecursiveDnsResolver {
    pub fn new(context: Arc<ServerContext>) -> RecursiveDnsResolver {
        RecursiveDnsResolver {
            context
        }
    }
}

impl DnsResolver for RecursiveDnsResolver {
    fn get_context(&self) -> Arc<ServerContext> {
        self.context.clone()
    }

    fn perform(&mut self, qname: &str, qtype: QueryType) -> Result<DnsPacket> {

        // Find the closest name server by splitting the label and progressively
        // moving towards the root servers. I.e. check "google.com", then "com",
        // and finally "".
        let mut tentative_ns = None;

        let labels = qname.split('.').collect::<Vec<&str>>();
        for lbl_idx in 0..labels.len()+1 {
            let mut domain = labels[lbl_idx..].join(".");
            if domain.is_empty() {
                domain = ".".to_owned();
            }

            match self.context.cache
                .lookup(&domain, QueryType::NS)
                .and_then(|qr| qr.get_unresolved_ns(&domain))
                .and_then(|ns| self.context.cache.lookup(&ns, QueryType::A))
                .and_then(|qr| qr.get_random_a()) {

                Some(addr) => {
                    tentative_ns = Some(addr);
                    break;
                },
                None => continue
            }
        }

        let mut ns = match tentative_ns {
            Some(x) => x,
            None => return Err(Error::new(ErrorKind::NotFound, "No DNS server found"))
        };

        let mut zones = HashSet::new();
        // Start querying name servers
        loop {
            println!("{}: attempting to lookup {:?} {} with ns {}", current_thread_name(), qtype, qname, ns);

            let ns_copy = ns.clone();
            let server = (ns_copy.as_str(), 53);
            let response = self.context.client.send_query(qname, qtype.clone(), server, false)?;

            // If we've got an actual answer, we're done!
            if !response.answers.is_empty() && response.header.res_code == ResultCode::NOERROR {
                let _ = self.context.cache.store(&response.answers);
                let _ = self.context.cache.store(&response.authorities);
                let _ = self.context.cache.store(&response.resources);
                return Ok(response.clone());
            }

            if response.header.res_code == ResultCode::NXDOMAIN {
                if let Some(ttl) = response.get_ttl_from_soa() {
                    let _ = self.context.cache.store_nxdomain(qname, qtype, ttl);
                }
                return Ok(response.clone());
            }

            if zones.contains(&response.get_ns_zone()) {
                return Err(Error::new(ErrorKind::NotFound, format!("Can not resolve {:?} {}", qtype, qname)));
            }

            // Otherwise, try to find a new nameserver based on NS and a
            // corresponding A record in the additional section
            if let Some(new_ns) = response.get_resolved_ns(qname) {
                // If there is such a record, we can retry the loop with that NS
                ns = new_ns.clone();
                let _ = self.context.cache.store(&response.answers);
                let _ = self.context.cache.store(&response.authorities);
                let _ = self.context.cache.store(&response.resources);
                let zone = response.get_ns_zone();
                if !zone.is_empty() {
                    zones.insert(zone);
                }
                continue;
            }

            // If not, we'll have to resolve the ip of a NS record
            let new_ns_name = match response.get_unresolved_ns(qname) {
                Some(x) => x,
                None => {
                    return Err(Error::new(ErrorKind::NotFound, format!("Can not resolve {:?} {}", qtype, qname)))
                }
            };

            // Recursively resolve the NS
            let recursive_response = self.resolve(&new_ns_name, QueryType::A, true)?;

            let zone = recursive_response.get_ns_zone();
            if !zone.is_empty() {
                zones.insert(zone);
            }

            // Pick a random IP and restart
            if let Some(new_ns) = recursive_response.get_random_a() {
                ns = new_ns.clone();
            } else {
                return Ok(response.clone())
            }
        }
    }
}

#[cfg(test)]
mod tests {

    use std::sync::Arc;

    use dns::protocol::{DnsPacket, QueryType, DnsRecord, ResultCode, TransientTtl};

    use super::*;

    use dns::context::ResolveStrategy;
    use dns::context::tests::create_test_context;

    #[test]
    fn test_forwarding_resolver() {
        let mut context = create_test_context(
            Box::new(|qname, _, _, _| {
                let mut packet = DnsPacket::new();

                if qname == "google.com" {
                    packet.answers.push(DnsRecord::A {
                        domain: "google.com".to_string(),
                        addr: "127.0.0.1".parse().unwrap(),
                        ttl: TransientTtl(3600)
                    });
                } else {
                    packet.header.res_code = ResultCode::NXDOMAIN;
                }

                Ok(packet)
            }));

        match Arc::get_mut(&mut context) {
            Some(mut ctx) => {
                ctx.resolve_strategy = ResolveStrategy::Forward {
                        host: "127.0.0.1".to_string(),
                        port: 53
                    };
            },
            None => panic!()
        }

        let mut resolver = context.create_resolver(context.clone());

        // First verify that we get a match back
        {
            let res = match resolver.resolve("google.com", QueryType::A, true) {
                Ok(x) => x,
                Err(_) => panic!()
            };

            assert_eq!(1, res.answers.len());

            match res.answers[0] {
                DnsRecord::A { ref domain, .. } => {
                    assert_eq!("google.com", domain);
                },
                _ => panic!()
            }
        };

        // Do the same lookup again, and verify that it's present in the cache
        // and that the counter has been updated
        {
            let res = match resolver.resolve("google.com", QueryType::A, true) {
                Ok(x) => x,
                Err(_) => panic!()
            };

            assert_eq!(1, res.answers.len());

            let list = match context.cache.list() {
                Ok(x) => x,
                Err(_) => panic!()
            };

            assert_eq!(1, list.len());

            assert_eq!("google.com", list[0].domain);
            assert_eq!(1, list[0].record_types.len());
            assert_eq!(1, list[0].hits);

        };

        // Do a failed lookup
        {
            let res = match resolver.resolve("yahoo.com", QueryType::A, true) {
                Ok(x) => x,
                Err(_) => panic!()
            };

            assert_eq!(0, res.answers.len());
            assert_eq!(ResultCode::NXDOMAIN, res.header.res_code);
        };

    }

    #[test]
    fn test_recursive_resolver_with_no_nameserver() {
        let context = create_test_context(
            Box::new(|_, _, _, _| {
                let mut packet = DnsPacket::new();
                packet.header.res_code = ResultCode::NXDOMAIN;
                Ok(packet)
            }));

        let mut resolver = context.create_resolver(context.clone());

        // Expect failure when no name servers are available
        if let Ok(_) = resolver.resolve("google.com", QueryType::A, true) {
            panic!();
        }
    }

    #[test]
    fn test_recursive_resolver_with_missing_a_record() {
        let context = create_test_context(
            Box::new(|_, _, _, _| {
                let mut packet = DnsPacket::new();
                packet.header.res_code = ResultCode::NXDOMAIN;
                Ok(packet)
            }));

        let mut resolver = context.create_resolver(context.clone());

        // Expect failure when no name servers are available
        if let Ok(_) = resolver.resolve("google.com", QueryType::A, true) {
            panic!();
        }

        // Insert name server, but no corresponding A record
        let mut nameservers = Vec::new();
        nameservers.push(DnsRecord::NS {
            domain: "".to_string(),
            host: "a.myroot.net".to_string(),
            ttl: TransientTtl(3600)
        });

        let _ = context.cache.store(&nameservers);

        if let Ok(_) = resolver.resolve("google.com", QueryType::A, true) {
            panic!();
        }
    }

    #[test]
    fn test_recursive_resolver_match_order() {
        let context = create_test_context(
            Box::new(|_, _, (server, _), _| {
                let mut packet = DnsPacket::new();

                if server == "127.0.0.1" {
                    packet.header.id = 1;

                    packet.answers.push(DnsRecord::A {
                        domain: "a.google.com".to_string(),
                        addr: "127.0.0.1".parse().unwrap(),
                        ttl: TransientTtl(3600)
                    });

                    return Ok(packet)
                }
                else if server == "127.0.0.2" {
                    packet.header.id = 2;

                    packet.answers.push(DnsRecord::A {
                        domain: "b.google.com".to_string(),
                        addr: "127.0.0.1".parse().unwrap(),
                        ttl: TransientTtl(3600)
                    });

                    return Ok(packet)
                }
                else if server == "127.0.0.3" {
                    packet.header.id = 3;

                    packet.answers.push(DnsRecord::A {
                        domain: "c.google.com".to_string(),
                        addr: "127.0.0.1".parse().unwrap(),
                        ttl: TransientTtl(3600)
                    });

                    return Ok(packet)
                }

                packet.header.id = 999;
                packet.header.res_code = ResultCode::NXDOMAIN;
                Ok(packet)
            }));

        let mut resolver = context.create_resolver(context.clone());

        // Expect failure when no name servers are available
        if let Ok(_) = resolver.resolve("google.com", QueryType::A, true) {
            panic!();
        }

        // Insert root servers
        {
            let mut nameservers = Vec::new();
            nameservers.push(DnsRecord::NS {
                domain: "".to_string(),
                host: "a.myroot.net".to_string(),
                ttl: TransientTtl(3600)
            });
            nameservers.push(DnsRecord::A {
                domain: "a.myroot.net".to_string(),
                addr: "127.0.0.1".parse().unwrap(),
                ttl: TransientTtl(3600)
            });

            let _ = context.cache.store(&nameservers);
        }

        match resolver.resolve("google.com", QueryType::A, true) {
            Ok(packet) => {
                assert_eq!(1, packet.header.id);
            },
            Err(_) => panic!()
        }

        // Insert TLD servers
        {
            let mut nameservers = Vec::new();
            nameservers.push(DnsRecord::NS {
                domain: "com".to_string(),
                host: "a.mytld.net".to_string(),
                ttl: TransientTtl(3600)
            });
            nameservers.push(DnsRecord::A {
                domain: "a.mytld.net".to_string(),
                addr: "127.0.0.2".parse().unwrap(),
                ttl: TransientTtl(3600)
            });

            let _ = context.cache.store(&nameservers);
        }

        match resolver.resolve("google.com", QueryType::A, true) {
            Ok(packet) => {
                assert_eq!(2, packet.header.id);
            },
            Err(_) => panic!()
        }

        // Insert authoritative servers
        {
            let mut nameservers = Vec::new();
            nameservers.push(DnsRecord::NS {
                domain: "google.com".to_string(),
                host: "ns1.google.com".to_string(),
                ttl: TransientTtl(3600)
            });
            nameservers.push(DnsRecord::A {
                domain: "ns1.google.com".to_string(),
                addr: "127.0.0.3".parse().unwrap(),
                ttl: TransientTtl(3600)
            });

            let _ = context.cache.store(&nameservers);
        }

        match resolver.resolve("google.com", QueryType::A, true) {
            Ok(packet) => {
                assert_eq!(3, packet.header.id);
            },
            Err(_) => panic!()
        }
    }

    #[test]
    fn test_recursive_resolver_successfully() {
        let context = create_test_context(
            Box::new(|qname, _, _, _| {
                let mut packet = DnsPacket::new();

                if qname == "google.com" {
                    packet.answers.push(DnsRecord::A {
                        domain: "google.com".to_string(),
                        addr: "127.0.0.1".parse().unwrap(),
                        ttl: TransientTtl(3600)
                    });
                } else {
                    packet.header.res_code = ResultCode::NXDOMAIN;

                    packet.authorities.push(DnsRecord::SOA {
                        domain: "google.com".to_string(),
                        r_name: "google.com".to_string(),
                        m_name: "google.com".to_string(),
                        serial: 0,
                        refresh: 3600,
                        retry: 3600,
                        expire: 3600,
                        minimum: 3600,
                        ttl: TransientTtl(3600)
                    });
                }

                Ok(packet)
            }));

        let mut resolver = context.create_resolver(context.clone());

        // Insert name servers
        let mut nameservers = Vec::new();
        nameservers.push(DnsRecord::NS {
            domain: "google.com".to_string(),
            host: "ns1.google.com".to_string(),
            ttl: TransientTtl(3600)
        });
        nameservers.push(DnsRecord::A {
            domain: "ns1.google.com".to_string(),
            addr: "127.0.0.1".parse().unwrap(),
            ttl: TransientTtl(3600)
        });

        let _ = context.cache.store(&nameservers);

        // Check that we can successfully resolve
        {
            let res = match resolver.resolve("google.com",
                                             QueryType::A,
                                             true) {
                Ok(x) => x,
                Err(_) => panic!()
            };

            assert_eq!(1, res.answers.len());

            match res.answers[0] {
                DnsRecord::A { ref domain, .. } => {
                    assert_eq!("google.com", domain);
                },
                _ => panic!()
            }
        };

        // And that we won't find anything for a domain that isn't present
        {
            let res = match resolver.resolve("foobar.google.com",
                                             QueryType::A,
                                             true) {
                Ok(x) => x,
                Err(_) => panic!()
            };

            assert_eq!(ResultCode::NXDOMAIN, res.header.res_code);
            assert_eq!(0, res.answers.len());
        };

        // Perform another successful query, that should hit the cache
        {
            let res = match resolver.resolve("google.com",
                                             QueryType::A,
                                             true) {
                Ok(x) => x,
                Err(_) => panic!()
            };

            assert_eq!(1, res.answers.len());
        };

        // Now check that the cache is used, and that the statistics is correct
        {
            let list = match context.cache.list() {
                Ok(x) => x,
                Err(_) => panic!()
            };

            assert_eq!(3, list.len());

            // Check statistics for google entry
            assert_eq!("google.com", list[1].domain);

            // Should have a NS record and an A record for a total of 2 record types
            assert_eq!(2, list[1].record_types.len());

            // Should have been hit two times for NS google.com and once for
            // A google.com
            assert_eq!(3, list[1].hits);

            assert_eq!("ns1.google.com", list[2].domain);
            assert_eq!(1, list[2].record_types.len());
            assert_eq!(2, list[2].hits);
        };
    }
}

