//! UDP and TCP server implementations for DNS

use std::io::{Result,Write};
use std::net::{UdpSocket, TcpListener, TcpStream, Shutdown};
use std::sync::{Arc,Mutex,Condvar};
use std::sync::mpsc::{channel, Sender};
use std::thread::{Builder,sleep};
use std::net::SocketAddr;
use std::collections::VecDeque;

use rand::random;

use dns::resolve::DnsResolver;
use dns::protocol::{DnsPacket, QueryType, DnsRecord, ResultCode};
use dns::buffer::{PacketBuffer, BytePacketBuffer, VectorPacketBuffer, StreamPacketBuffer};
use dns::context::ServerContext;
use dns::netutil::{read_packet_length, write_packet_length};
use dns::filter::DnsFilter;
use dns::utils::current_time_millis;
use std::time::Duration;
use std::io::ErrorKind;

macro_rules! return_or_report {
    ( $x:expr, $message:expr ) => {
        match $x {
            Ok(res) => res,
            Err(_) => {
                println!($message);
                return;
            }
        }
    }
}

macro_rules! ignore_or_report {
    ( $x:expr, $message:expr ) => {
        match $x {
            Ok(_) => {},
            Err(_) => {
                println!($message);
                return;
            }
        };
    }
}

/// Common trait for DNS servers
pub trait DnsServer {

    /// Initialize the server and start listenening
    ///
    /// This method should _NOT_ block. Rather, servers are expected to spawn a new
    /// thread to handle requests and return immediately.
    fn run_server(self) -> Result<()>;
}

/// Utility function for resolving domains referenced in for example CNAME or SRV
/// records. This usually spares the client from having to perform additional lookups.
fn resolve_cnames(lookup_list: &[DnsRecord], results: &mut Vec<DnsPacket>, resolver: &mut Box<DnsResolver>, depth: u16)
{
    if depth > 10 {
        return;
    }

    for ref rec in lookup_list {
        match **rec {
            DnsRecord::CNAME { ref host, .. } |
            DnsRecord::SRV { ref host, .. } => {
                if let Ok(result2) = resolver.resolve(host, QueryType::A, true) {
                    let new_unmatched = result2.get_unresolved_cnames();
                    results.push(result2);

                    resolve_cnames(&new_unmatched, results, resolver, depth+1);
                }
            },
            _ => {}
        }
    }
}

/// Perform the actual work for a query
///
/// Incoming requests are validated to make sure they are well formed and adhere
/// to the server configuration. If so, the request will be passed on to the
/// active resolver and a query will be performed. It will also resolve some
/// possible references within the query, such as CNAME hosts.
///
/// This function will always return a valid packet, even if the request could not
/// be performed, since we still want to send something back to the client.
pub fn execute_query(context: Arc<ServerContext>, request: &DnsPacket) -> DnsPacket
{
    let mut packet = DnsPacket::new();
    packet.header.id = request.header.id;
    packet.header.recursion_available = context.allow_recursive;
    packet.header.response = true;

    if request.header.recursion_desired && !context.allow_recursive {
        packet.header.res_code = ResultCode::REFUSED;
    }
    else if request.questions.is_empty() {
        packet.header.res_code = ResultCode::FORMERR;
    }
    else {
        let mut results = Vec::new();

        let question = &request.questions[0];
        packet.questions.push(question.clone());

        if context.filter.contains(&question.name) {
            println!("Blocking domain {}, record {:?}", question.name, question.qtype);
            DnsFilter::fill_blocked_response(&mut packet);
            return packet;
        }

        let mut resolver = context.create_resolver(context.clone());
        let res_code = match resolver.resolve(&question.name,
                                             question.qtype,
                                             request.header.recursion_desired) {

            Ok(result) => {
                let res_code = result.header.res_code;

                let unmatched = result.get_unresolved_cnames();
                results.push(result);

                resolve_cnames(&unmatched, &mut results, &mut resolver, 0);

                res_code
            },
            Err(err) => {
                println!("Failed to resolve {:?} {}: {:?}", question.qtype, question.name, err);
                ResultCode::SERVFAIL
            }
        };

        packet.header.res_code = res_code;

        for result in results {
            for rec in result.answers {
                packet.answers.push(rec);
            }
            for rec in result.authorities {
                packet.authorities.push(rec);
            }
            for rec in result.resources {
                packet.resources.push(rec);
            }
        }
    }

    packet
}

/// The UDP server
///
/// Accepts DNS queries through UDP, and uses the `ServerContext` to determine
/// how to service the request. Packets are read on a single thread, after which
/// a new thread is spawned to service the request asynchronously.
pub struct DnsUdpServer {
    context: Arc<ServerContext>,
    request_queue: Arc<Mutex<VecDeque<(SocketAddr, DnsPacket)>>>,
    request_cond: Arc<Condvar>,
    thread_count: usize
}

impl DnsUdpServer {
    pub fn new(context: Arc<ServerContext>, thread_count: usize) -> DnsUdpServer {
        DnsUdpServer {
            context,
            request_queue: Arc::new(Mutex::new(VecDeque::new())),
            request_cond: Arc::new(Condvar::new()),
            thread_count
        }
    }
}

impl DnsServer for DnsUdpServer {

    /// Launch the server
    ///
    /// This method takes ownership of the server, preventing the method from
    /// being called multiple times.
    fn run_server(self) -> Result<()> {

        // Bind the socket
        let socket = UdpSocket::bind((self.context.dns_bind_ip.as_ref(), self.context.dns_port))?;
        socket.set_read_timeout(Some(Duration::from_millis(100))).unwrap();

        // Spawn threads for handling requests
        for thread_id in 0..self.thread_count {
            let socket_clone = match socket.try_clone() {
                Ok(x) => x,
                Err(e) => {
                    println!("Failed to clone socket when starting UDP server: {:?}", e);
                    continue
                }
            };

            let context = self.context.clone();
            let request_cond = self.request_cond.clone();
            let request_queue = self.request_queue.clone();

            let name = "DnsUdpServer-request-".to_string() + &thread_id.to_string();
            let _ = Builder::new().name(name).spawn(move || {
                loop {
                    // Acquire lock, and wait on the condition until data is available.
                    // Then proceed with popping an entry of the queue.
                    let (src, request) = match request_queue.lock().ok()
                        .and_then(|x| request_cond.wait(x).ok())
                        .and_then(|mut x| x.pop_front()) {
                        Some(x) => x,
                        None => {
                            println!("Not expected to happen!");
                            continue;
                        }
                    };

                    let mut size_limit = 512;

                    // Check for EDNS
                    if request.resources.len() == 1 {
                        if let DnsRecord::OPT { packet_len, .. } = request.resources[0] {
                            size_limit = packet_len as usize;
                        }
                    }

                    // Create a response buffer, and ask the context for an appropriate resolver
                    let mut res_buffer = VectorPacketBuffer::new();

                    let mut packet = execute_query(context.clone(), &request);
                    let _ = packet.write(&mut res_buffer, size_limit);

                    // Fire off the response
                    let len = res_buffer.pos();
                    let data = return_or_report!(res_buffer.get_range(0, len), "Failed to get buffer data");
                    ignore_or_report!(socket_clone.send_to(data, src), "Failed to send response packet");
                    // Incrementing and printing statistics
                    let request_time = current_time_millis() - request.get_start_time();
                    let mut lock = context.statistics.lock().unwrap();
                    lock.add_request_time(request_time, true);
                }
            })?;
        }

        let threads_count = self.context.clone().threads_udp;
        let mut queue_len = 0;
        // Start servicing requests
        let _ = Builder::new().name("DnsUdpServer-incoming".into()).spawn(move || {
            loop {
                // If we have a lot of requests in a queue we need to serve them first
                if queue_len > 0 {
                    {
                        queue_len = match self.request_queue.lock() {
                            Ok(queue) => queue.len(),
                            Err(_e) => 0
                        };
                    }
                    println!("Queue size is {}", queue_len);
                    self.request_cond.notify_one();
                    if queue_len> threads_count {
                        sleep(Duration::from_millis(10));
                        self.request_cond.notify_one();
                    }
                }

                // Read a query packet
                let mut req_buffer = BytePacketBuffer::new();
                let (_, src) = match socket.recv_from(&mut req_buffer.buf) {
                    Ok(x) => x,
                    Err(e) => {
                        if e.kind() != ErrorKind::TimedOut && e.raw_os_error() != Some(11) {
                            println!("Failed to read from UDP socket: {:?}", e);
                        }
                        continue;
                    }
                };

                let start_time = current_time_millis();

                // Parse it
                let mut request = match DnsPacket::from_buffer(&mut req_buffer) {
                    Ok(x) => x,
                    Err(e) => {
                        println!("Failed to parse UDP query packet: {:?}", e);
                        continue;
                    }
                };

                request.set_start_time(start_time);

                // Acquire lock, add request to queue, and notify waiting threads using the condition.
                match self.request_queue.lock() {
                    Ok(mut queue) => {
                        queue.push_back((src, request));
                        self.request_cond.notify_one();
                        queue_len = queue.len();
                    },
                    Err(e) => {
                        println!("Failed to send UDP request for processing: {}", e);
                    }
                }
            }
        })?;

        Ok(())
    }
}

/// TCP DNS server
pub struct DnsTcpServer {
    context: Arc<ServerContext>,
    senders: Vec<Sender<TcpStream>>,
    thread_count: usize
}

impl DnsTcpServer {
    pub fn new(context: Arc<ServerContext>, thread_count: usize) -> DnsTcpServer {
        DnsTcpServer {
            context,
            senders: Vec::new(),
            thread_count
        }
    }
}

impl DnsServer for DnsTcpServer {
    fn run_server(mut self) -> Result<()> {
        let socket = TcpListener::bind((self.context.dns_bind_ip.as_ref(), self.context.dns_port))?;

        // Spawn threads for handling requests, and create the channels
        for thread_id in 0..self.thread_count {
            let (tx, rx) = channel();
            self.senders.push(tx);

            let mut context = self.context.clone();

            let name = "DnsTcpServer-request-".to_string() + &thread_id.to_string();
            let _ = Builder::new().name(name).spawn(move || {
                loop {
                    let mut stream = match rx.recv() {
                        Ok(x) => x,
                        Err(_) => continue
                    };

                    // When DNS packets are sent over TCP, they're prefixed with a two byte
                    // length. We don't really need to know the length in advance, so we
                    // just move past it and continue reading as usual
                    ignore_or_report!(read_packet_length(&mut stream), "Failed to read query packet length");

                    let mut request = {
                        let mut stream_buffer = StreamPacketBuffer::new(&mut stream);
                        return_or_report!(DnsPacket::from_buffer(&mut stream_buffer), "Failed to read query packet")
                    };

                    let start_time = current_time_millis();
                    request.set_start_time(start_time);

                    let mut res_buffer = VectorPacketBuffer::new();

                    let mut packet = execute_query(context.clone(), &request);
                    ignore_or_report!(packet.write(&mut res_buffer, 0xFFFF), "Failed to write packet to buffer");

                    // As is the case for incoming queries, we need to send a 2 byte length
                    // value before handing of the actual packet.
                    let len = res_buffer.pos();
                    ignore_or_report!(write_packet_length(&mut stream, len), "Failed to write packet size");

                    // Now we can go ahead and write the actual packet
                    let data = return_or_report!(res_buffer.get_range(0, len), "Failed to get packet data");

                    ignore_or_report!(stream.write(data), "Failed to write response packet");
                    ignore_or_report!(stream.shutdown(Shutdown::Both), "Failed to shutdown socket");
                    // Incrementing and printing statistics
                    let request_time = current_time_millis() - request.get_start_time();
                    let mut lock = context.statistics.lock().unwrap();
                    lock.add_request_time(request_time, false);
                }
            })?;
        }

        let _ = Builder::new().name("DnsTcpServer-incoming".into()).spawn(move || {
            for wrap_stream in socket.incoming() {
                let stream = match wrap_stream {
                    Ok(stream) => stream,
                    Err(err) => {
                        println!("Failed to accept TCP connection: {:?}", err);
                        continue;
                    }
                };

                // Hand it off to a worker thread
                let thread_no = random::<usize>() % self.thread_count;
                match self.senders[thread_no].send(stream) {
                    Ok(_) => {},
                    Err(e) => {
                        println!("Failed to send TCP request for processing on thread {}: {}", thread_no, e);
                    }
                }
            }
        })?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use std::sync::Arc;
    use std::net::Ipv4Addr;
    use std::io::{Error, ErrorKind};

    use dns::protocol::{DnsPacket, DnsQuestion, QueryType, DnsRecord, ResultCode, TransientTtl};

    use super::*;

    use dns::context::ResolveStrategy;
    use dns::context::tests::create_test_context;

    fn build_query(qname: &str, qtype: QueryType) -> DnsPacket {
        let mut query_packet = DnsPacket::new();
        query_packet.header.recursion_desired = true;

        query_packet.questions.push(DnsQuestion::new(qname.into(), qtype));

        query_packet
    }

    #[test]
    fn test_execute_query() {

        // Construct a context to execute some queries successfully
        let mut context = create_test_context(
            Box::new(|qname, qtype, _, _| {
                let mut packet = DnsPacket::new();

                if qname == "google.com" {
                    packet.answers.push(DnsRecord::A {
                        domain: "google.com".to_string(),
                        addr: "127.0.0.1".parse::<Ipv4Addr>().unwrap(),
                        ttl: TransientTtl(3600)
                    });
                } else if qname == "www.facebook.com" && qtype == QueryType::CNAME {
                    packet.answers.push(DnsRecord::CNAME {
                        domain: "www.facebook.com".to_string(),
                        host: "cdn.facebook.com".to_string(),
                        ttl: TransientTtl(3600)
                    });
                    packet.answers.push(DnsRecord::A {
                        domain: "cdn.facebook.com".to_string(),
                        addr: "127.0.0.1".parse::<Ipv4Addr>().unwrap(),
                        ttl: TransientTtl(3600)
                    });
                } else if qname == "www.microsoft.com" && qtype == QueryType::CNAME {
                    packet.answers.push(DnsRecord::CNAME {
                        domain: "www.microsoft.com".to_string(),
                        host: "cdn.microsoft.com".to_string(),
                        ttl: TransientTtl(3600)
                    });
                } else if qname == "cdn.microsoft.com" && qtype == QueryType::A {
                    packet.answers.push(DnsRecord::A {
                        domain: "cdn.microsoft.com".to_string(),
                        addr: "127.0.0.1".parse::<Ipv4Addr>().unwrap(),
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

        // A successful resolve
        {
            let res = execute_query(context.clone(),
                                    &build_query("google.com", QueryType::A));
            assert_eq!(1, res.answers.len());

            match res.answers[0] {
                DnsRecord::A { ref domain, .. } => {
                    assert_eq!("google.com", domain);
                },
                _ => panic!()
            }
        };

        // A successful resolve, that also resolves a CNAME without recursive lookup
        {
            let res = execute_query(context.clone(),
                                    &build_query("www.facebook.com", QueryType::CNAME));
            assert_eq!(2, res.answers.len());

            match res.answers[0] {
                DnsRecord::CNAME { ref domain, .. } => {
                    assert_eq!("www.facebook.com", domain);
                },
                _ => panic!()
            }

            match res.answers[1] {
                DnsRecord::A { ref domain, .. } => {
                    assert_eq!("cdn.facebook.com", domain);
                },
                _ => panic!()
            }
        };

        // A successful resolve, that also resolves a CNAME through recursive lookup
        {
            let res = execute_query(context.clone(),
                                    &build_query("www.microsoft.com", QueryType::CNAME));
            assert_eq!(2, res.answers.len());

            match res.answers[0] {
                DnsRecord::CNAME { ref domain, .. } => {
                    assert_eq!("www.microsoft.com", domain);
                },
                _ => panic!()
            }

            match res.answers[1] {
                DnsRecord::A { ref domain, .. } => {
                    assert_eq!("cdn.microsoft.com", domain);
                },
                _ => panic!()
            }
        };

        // An unsuccessful resolve, but without any error
        {
            let res = execute_query(context.clone(),
                                    &build_query("yahoo.com", QueryType::A));
            assert_eq!(ResultCode::NXDOMAIN, res.header.res_code);
            assert_eq!(0, res.answers.len());
        };

        // Disable recursive resolves to generate a failure
        match Arc::get_mut(&mut context) {
            Some(mut ctx) => {
                ctx.allow_recursive = false;
            },
            None => panic!()
        }

        // This should generate an error code, since recursive resolves are
        // no longer allowed
        {
            let res = execute_query(context.clone(),
                                    &build_query("yahoo.com", QueryType::A));
            assert_eq!(ResultCode::REFUSED, res.header.res_code);
            assert_eq!(0, res.answers.len());
        };


        // Send a query without a question, which should fail with an error code
        {
            let query_packet = DnsPacket::new();
            let res = execute_query(context.clone(), &query_packet);
            assert_eq!(ResultCode::FORMERR, res.header.res_code);
            assert_eq!(0, res.answers.len());
        };

        // Now construct a context where the dns client will return a failure
        let mut context2 = create_test_context(
            Box::new(|_, _, _, _| {
                Err(Error::new(ErrorKind::NotFound, "Fail"))
            }));

        match Arc::get_mut(&mut context2) {
            Some(mut ctx) => {
                ctx.resolve_strategy = ResolveStrategy::Forward {
                        host: "127.0.0.1".to_string(),
                        port: 53
                    };
            },
            None => panic!()
        }

        // We expect this to set the server failure rescode
        {
            let res = execute_query(context2.clone(),
                                    &build_query("yahoo.com", QueryType::A));
            assert_eq!(ResultCode::SERVFAIL, res.header.res_code);
            assert_eq!(0, res.answers.len());
        };

    }
}

