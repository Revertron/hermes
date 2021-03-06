//! hermes documentation

#![cfg_attr(feature="clippy", feature(plugin))]
#![cfg_attr(feature="clippy", plugin(clippy))]

pub mod dns;
//pub mod web;

extern crate rand;
extern crate chrono;
//extern crate tiny_http;
//extern crate rustc_serialize;
extern crate ascii;
extern crate handlebars;
extern crate regex;
extern crate getopts;

use std::env;
use std::sync::Arc;
use std::net::Ipv4Addr;

use getopts::Options;

use dns::server::{DnsServer,DnsUdpServer,DnsTcpServer};
use dns::protocol::{DnsRecord,TransientTtl};
use dns::context::{ServerContext, ResolveStrategy};
//use web::server::WebServer;
//use web::cache::CacheAction;
//use web::authority::{AuthorityAction,ZoneAction};
//use web::index::IndexAction;

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} [options]", program);
    print!("{}", opts.usage(&brief));
}

fn main() {

    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();

    let mut opts = Options::new();
    opts.optflag("h", "help", "print this help menu");
    opts.optflag("a", "authority", "disable support for recursive lookups, and serve only local zones");
    opts.optopt("f", "forward", "forward replies to specified dns server", "SERVER");
    opts.optopt("t", "threads", "count of precreated threads in pools", "32");
    opts.optopt("p", "port", "listening port", "53");

    let opt_matches = match opts.parse(&args[1..]) {
        Ok(m) => { m }
        Err(f) => { panic!(f.to_string()) }
    };

    if opt_matches.opt_present("h") {
        print_usage(&program, opts);
        return;
    }

    let mut context = Arc::new(ServerContext::new());

    if let Some(ctx) = Arc::get_mut(&mut context) {

        let mut index_rootservers = true;
        if opt_matches.opt_present("f") {
            match opt_matches.opt_str("f").and_then(|x| x.parse::<Ipv4Addr>().ok()) {
                Some(ip) => {
                    ctx.resolve_strategy = ResolveStrategy::Forward {
                        host: ip.to_string(),
                        port: 53
                    };
                    index_rootservers = false;
                    println!("Running as forwarder");
                },
                None => {
                    println!("Forward parameter must be a valid Ipv4 address");
                    return;
                }
            }
        }

        if opt_matches.opt_present("t") {
            match opt_matches.opt_str("t").and_then(|x| x.parse::<usize>().ok()) {
                Some(threads) => {
                    ctx.threads_udp = threads;
                    ctx.threads_tcp = threads;
                    println!("Using {} threads in UDP and TCP server pools", threads);
                },
                None => {
                    println!("Threads parameter must be a positive number");
                    return;
                }
            }
        }

        if opt_matches.opt_present("p") {
            match opt_matches.opt_str("p").and_then(|x| x.parse::<u16>().ok()) {
                Some(port) => {
                    ctx.dns_port = port;
                    println!("Using port {} for DNS", port);
                },
                None => {
                    println!("Port number must be positive number in 1..65535 range");
                    return;
                }
            }
        }

        if opt_matches.opt_present("a") {
            ctx.allow_recursive = false;
        }

        match ctx.initialize() {
            Ok(_) => {},
            Err(e) => {
                println!("Server failed to initialize: {:?}", e);
                return;
            }
        }

        if index_rootservers {
            let _ = ctx.cache.store(&get_rootservers());
        }
    }

    // Start DNS servers
    if context.threads_udp > 0 {
        let udp_server = DnsUdpServer::new(context.clone(), context.threads_udp);
        if let Err(e) = udp_server.run_server() {
            println!("Failed to bind UDP listener: {:?}", e);
        }
    }

    if context.threads_tcp > 0 {
        let tcp_server = DnsTcpServer::new(context.clone(), context.threads_tcp);
        if let Err(e) = tcp_server.run_server() {
            println!("Failed to bind TCP listener: {:?}", e);
        }
    }

    println!("Listening on port {}", context.dns_port);

    loop {
        use std::thread;
        thread::sleep(std::time::Duration::from_millis(500));
    }
    // Start web server
    /*if context.enable_api {
        let mut webserver = WebServer::new(context.clone());

        webserver.register_action(Box::new(CacheAction::new(context.clone())));
        webserver.register_action(Box::new(AuthorityAction::new(context.clone())));
        webserver.register_action(Box::new(ZoneAction::new(context.clone())));
        webserver.register_action(Box::new(IndexAction::new(context.clone())));

        webserver.run_webserver();
    }*/
}

fn get_rootservers() -> Vec<DnsRecord>
{
    let mut rootservers = Vec::new();

    rootservers.push(DnsRecord::NS { domain: ".".to_string(), host: "a.root-servers.net".to_string(), ttl: TransientTtl(3600000) });
    rootservers.push(DnsRecord::A{ domain: "a.root-servers.net".to_string(), addr: "198.41.0.4".parse().unwrap(),ttl: TransientTtl(3600000) });
    //rootservers.push(DnsRecord::AAAA { domain: "a.root-servers.net".to_string(), addr: "2001:503:ba3e::2:30".parse().unwrap(), ttl: TransientTtl(3600000) });

    rootservers.push(DnsRecord::NS { domain: ".".to_string(), host: "b.root-servers.net".to_string(), ttl: TransientTtl(3600000) });
    rootservers.push(DnsRecord::A{ domain: "b.root-servers.net".to_string(), addr: "199.9.14.201".parse().unwrap(),ttl: TransientTtl(3600000) });
    //rootservers.push(DnsRecord::AAAA { domain: "b.root-servers.net".to_string(), addr: "2001:500:84::b".parse().unwrap(), ttl: TransientTtl(3600000) });

    rootservers.push(DnsRecord::NS { domain: ".".to_string(), host: "c.root-servers.net".to_string(), ttl: TransientTtl(3600000) });
    rootservers.push(DnsRecord::A{ domain: "c.root-servers.net".to_string(), addr: "192.33.4.12".parse().unwrap(),ttl: TransientTtl(3600000) });
    //rootservers.push(DnsRecord::AAAA { domain: "c.root-servers.net".to_string(), addr: "2001:500:2::c".parse().unwrap(), ttl: TransientTtl(3600000) });

    rootservers.push(DnsRecord::NS { domain: ".".to_string(), host: "d.root-servers.net".to_string(), ttl: TransientTtl(3600000) });
    rootservers.push(DnsRecord::A{ domain: "d.root-servers.net".to_string(), addr: "199.7.91.13".parse().unwrap(),ttl: TransientTtl(3600000) });
    //rootservers.push(DnsRecord::AAAA { domain: "d.root-servers.net".to_string(), addr: "2001:500:2d::d".parse().unwrap(), ttl: TransientTtl(3600000) });

    rootservers.push(DnsRecord::NS { domain: ".".to_string(), host: "e.root-servers.net".to_string(), ttl: TransientTtl(3600000) });
    rootservers.push(DnsRecord::A{ domain: "e.root-servers.net".to_string(), addr: "192.203.230.10".parse().unwrap(),ttl: TransientTtl(3600000) });

    rootservers.push(DnsRecord::NS { domain: ".".to_string(), host: "f.root-servers.net".to_string(), ttl: TransientTtl(3600000) });
    rootservers.push(DnsRecord::A{ domain: "f.root-servers.net".to_string(), addr: "192.5.5.241".parse().unwrap(),ttl: TransientTtl(3600000) });
    //rootservers.push(DnsRecord::AAAA { domain: "f.root-servers.net".to_string(), addr: "2001:500:2f::f".parse().unwrap(), ttl: TransientTtl(3600000) });

    rootservers.push(DnsRecord::NS { domain: ".".to_string(),  host: "g.root-servers.net".to_string(), ttl: TransientTtl(3600000) });
    rootservers.push(DnsRecord::A{ domain: "g.root-servers.net".to_string(), addr: "192.112.36.4".parse().unwrap(),ttl: TransientTtl(3600000) });

    rootservers.push(DnsRecord::NS { domain: ".".to_string(), host: "h.root-servers.net".to_string(), ttl: TransientTtl(3600000) });
    rootservers.push(DnsRecord::A{ domain: "h.root-servers.net".to_string(), addr: "198.97.190.53".parse().unwrap(),ttl: TransientTtl(3600000) });
    //rootservers.push(DnsRecord::AAAA { domain: "h.root-servers.net".to_string(), addr: "2001:500:1::53".parse().unwrap(), ttl: TransientTtl(3600000) });

    rootservers.push(DnsRecord::NS { domain: ".".to_string(), host: "i.root-servers.net".to_string(), ttl: TransientTtl(3600000) });
    rootservers.push(DnsRecord::A{ domain: "i.root-servers.net".to_string(), addr: "192.36.148.17".parse().unwrap(),ttl: TransientTtl(3600000) });
    //rootservers.push(DnsRecord::AAAA { domain: "i.root-servers.net".to_string(), addr: "2001:7fe::53".parse().unwrap(), ttl: TransientTtl(3600000) });

    rootservers.push(DnsRecord::NS { domain: ".".to_string(), host: "j.root-servers.net".to_string(), ttl: TransientTtl(3600000) });
    rootservers.push(DnsRecord::A{ domain: "j.root-servers.net".to_string(), addr: "192.58.128.30".parse().unwrap(),ttl: TransientTtl(3600000) });
    //rootservers.push(DnsRecord::AAAA { domain: "j.root-servers.net".to_string(), addr: "2001:503:c27::2:30".parse().unwrap(), ttl: TransientTtl(3600000) });

    rootservers.push(DnsRecord::NS { domain: ".".to_string(), host: "k.root-servers.net".to_string(), ttl: TransientTtl(3600000) });
    rootservers.push(DnsRecord::A{ domain: "k.root-servers.net".to_string(), addr: "193.0.14.129".parse().unwrap(),ttl: TransientTtl(3600000) });
    //rootservers.push(DnsRecord::AAAA { domain: "k.root-servers.net".to_string(), addr: "2001:7fd::1".parse().unwrap(), ttl: TransientTtl(3600000) });

    rootservers.push(DnsRecord::NS { domain: ".".to_string(), host: "l.root-servers.net".to_string(), ttl: TransientTtl(3600000) });
    rootservers.push(DnsRecord::A{ domain: "l.root-servers.net".to_string(), addr: "199.7.83.42".parse().unwrap(),ttl: TransientTtl(3600000) });
    //rootservers.push(DnsRecord::AAAA { domain: "l.root-servers.net".to_string(), addr: "2001:500:3::42".parse().unwrap(), ttl: TransientTtl(3600000) });

    rootservers.push(DnsRecord::NS { domain: ".".to_string(), host: "m.root-servers.net".to_string(), ttl: TransientTtl(3600000) });
    rootservers.push(DnsRecord::A{ domain: "m.root-servers.net".to_string(), addr: "202.12.27.33".parse().unwrap(),ttl: TransientTtl(3600000) });
    //rootservers.push(DnsRecord::AAAA { domain: "m.root-servers.net".to_string(), addr: "2001:dc3::35".parse().unwrap(), ttl: TransientTtl(3600000) });

    rootservers
}
