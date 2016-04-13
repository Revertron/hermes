//! implements the DNS protocol in a transport agnostic fashion

use std::fmt;
use std::net::{Ipv4Addr,Ipv6Addr};
use std::io::{Result, Read};
//use std::io::{Error, ErrorKind};
use rand::random;

use dns::buffer::{PacketBuffer, VectorPacketBuffer};

/// QueryType represents the requested Record Type of a query
///
/// The specific type UNKNOWN that an integer parameter in order to retain the
/// id of an unknown query when compiling the reply. An integer can be converted
/// to a querytype using the `from_num` function, and back to an integer using
/// the `to_num` method.
#[derive(PartialEq,Eq,Debug,Clone,Hash)]
pub enum QueryType {
    UNKNOWN(u16),
    A, // 1
    NS, // 2
    CNAME, // 5
    SOA, // 6
    MX, // 15
    TXT, // 16
    AAAA, // 28
    SRV, // 33
    OPT // 41
}

impl QueryType {
    pub fn to_num(&self) -> u16 {
        match *self {
            QueryType::UNKNOWN(x) => x,
            QueryType::A => 1,
            QueryType::NS => 2,
            QueryType::CNAME => 5,
            QueryType::SOA => 6,
            QueryType::MX => 15,
            QueryType::TXT => 16,
            QueryType::AAAA => 28,
            QueryType::SRV => 33,
            QueryType::OPT => 41
        }
    }

    pub fn from_num(num: u16) -> QueryType {
        match num {
            1 => QueryType::A,
            2 => QueryType::NS,
            5 => QueryType::CNAME,
            6 => QueryType::SOA,
            15 => QueryType::MX,
            16 => QueryType::TXT,
            28 => QueryType::AAAA,
            33 => QueryType::SRV,
            41 => QueryType::OPT,
            _ => QueryType::UNKNOWN(num)
        }
    }
}

/// DnsRecord is the primary representation of a DNS record
///
/// This enumeration is used for reading as well as writing records, from network
/// and from disk (for storage of authority data).
#[derive(Debug,Clone,PartialEq,Eq,Hash,PartialOrd,Ord)]
#[allow(dead_code)]
pub enum DnsRecord {
    UNKNOWN {
        domain: String,
        qtype: u16,
        data_len: u16,
        ttl: u32
    }, // 0
    A {
        domain: String,
        addr: Ipv4Addr,
        ttl: u32
    }, // 1
    NS {
        domain: String,
        host: String,
        ttl: u32
    }, // 2
    CNAME {
        domain: String,
        host: String,
        ttl: u32
    }, // 5
    SOA {
        domain: String,
        mname: String,
        rname: String,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
        ttl: u32
    }, // 6
    MX {
        domain: String,
        priority: u16,
        host: String,
        ttl: u32
    }, // 15
    TXT {
        domain: String,
        data: String,
        ttl: u32
    }, // 16
    AAAA {
        domain: String,
        addr: Ipv6Addr,
        ttl: u32
    }, // 28
    SRV {
        domain: String,
        priority: u16,
        weight: u16,
        port: u16,
        host: String,
        ttl: u32
    }, // 33
    OPT {
        packet_len: u16,
        flags: u32,
        data: String
    } // 41
}

impl DnsRecord {
    pub fn read<T: PacketBuffer>(buffer: &mut T) -> Result<DnsRecord> {
        let mut domain = String::new();
        let _ = try!(buffer.read_qname(&mut domain));

        let qtype_num = try!(buffer.read_u16());
        let qtype = QueryType::from_num(qtype_num);
        let class = try!(buffer.read_u16());
        let ttl = try!(buffer.read_u32());
        let data_len = try!(buffer.read_u16());

        match qtype {
            QueryType::A  => {
                let raw_addr = try!(buffer.read_u32());
                let addr = Ipv4Addr::new(((raw_addr >> 24) & 0xFF) as u8,
                                         ((raw_addr >> 16) & 0xFF) as u8,
                                         ((raw_addr >> 8) & 0xFF) as u8,
                                         ((raw_addr >> 0) & 0xFF) as u8);

                return Ok(DnsRecord::A {
                    domain: domain,
                    addr: addr,
                    ttl: ttl
                });
            },
            QueryType::AAAA => {
                let raw_addr1 = try!(buffer.read_u32());
                let raw_addr2 = try!(buffer.read_u32());
                let raw_addr3 = try!(buffer.read_u32());
                let raw_addr4 = try!(buffer.read_u32());
                let addr = Ipv6Addr::new(((raw_addr1 >> 16) & 0xFFFF) as u16,
                                         ((raw_addr1 >> 0) & 0xFFFF) as u16,
                                         ((raw_addr2 >> 16) & 0xFFFF) as u16,
                                         ((raw_addr2 >> 0) & 0xFFFF) as u16,
                                         ((raw_addr3 >> 16) & 0xFFFF) as u16,
                                         ((raw_addr3 >> 0) & 0xFFFF) as u16,
                                         ((raw_addr4 >> 16) & 0xFFFF) as u16,
                                         ((raw_addr4 >> 0) & 0xFFFF) as u16);

                return Ok(DnsRecord::AAAA {
                    domain: domain,
                    addr: addr,
                    ttl: ttl
                });
            },
            QueryType::NS => {
                let mut ns = String::new();
                try!(buffer.read_qname(&mut ns));

                return Ok(DnsRecord::NS {
                    domain: domain,
                    host: ns,
                    ttl: ttl
                });
            },
            QueryType::CNAME => {
                let mut cname = String::new();
                try!(buffer.read_qname(&mut cname));

                return Ok(DnsRecord::CNAME {
                    domain: domain,
                    host: cname,
                    ttl: ttl
                });
            },
            QueryType::SRV => {
                let priority = try!(buffer.read_u16());
                let weight = try!(buffer.read_u16());
                let port = try!(buffer.read_u16());

                let mut srv = String::new();
                try!(buffer.read_qname(&mut srv));

                return Ok(DnsRecord::SRV {
                    domain: domain,
                    priority: priority,
                    weight: weight,
                    port: port,
                    host: srv,
                    ttl: ttl
                });
            },
            QueryType::MX => {
                let priority = try!(buffer.read_u16());
                let mut mx = String::new();
                try!(buffer.read_qname(&mut mx));

                return Ok(DnsRecord::MX {
                    domain: domain,
                    priority: priority,
                    host: mx,
                    ttl: ttl
                });
            },
            QueryType::SOA => {
                let mut mname = String::new();
                try!(buffer.read_qname(&mut mname));

                let mut rname = String::new();
                try!(buffer.read_qname(&mut rname));

                let serial = try!(buffer.read_u32());
                let refresh = try!(buffer.read_u32());
                let retry = try!(buffer.read_u32());
                let expire = try!(buffer.read_u32());
                let minimum = try!(buffer.read_u32());

                return Ok(DnsRecord::SOA {
                    domain: domain,
                    mname: mname,
                    rname: rname,
                    serial: serial,
                    refresh: refresh,
                    retry: retry,
                    expire: expire,
                    minimum: minimum,
                    ttl: ttl
                });
            },
            QueryType::TXT => {
                let mut txt = String::new();

                let cur_pos = buffer.pos();
                txt.push_str(&String::from_utf8_lossy(try!(buffer.get_range(cur_pos, data_len as usize))));

                try!(buffer.step(data_len as usize));

                return Ok(DnsRecord::TXT {
                    domain: domain,
                    data: txt,
                    ttl: ttl
                });
            },
            QueryType::OPT => {
                let mut data = String::new();

                let cur_pos = buffer.pos();
                data.push_str(&String::from_utf8_lossy(try!(buffer.get_range(cur_pos, data_len as usize))));
                try!(buffer.step(data_len as usize));

                return Ok(DnsRecord::OPT {
                    packet_len: class,
                    flags: ttl,
                    data: data
                });
            },
            QueryType::UNKNOWN(_) => {
                try!(buffer.step(data_len as usize));

                return Ok(DnsRecord::UNKNOWN { domain: domain,
                                                    qtype: qtype_num,
                                                    data_len: data_len,
                                                    ttl: ttl });
            }
        }
    }

    pub fn write<T: PacketBuffer>(&self, buffer: &mut T) -> Result<usize> {

        let start_pos = buffer.pos();

        match *self {
            DnsRecord::A { ref domain, ref addr, ttl } => {
                try!(buffer.write_qname(domain));
                try!(buffer.write_u16(QueryType::A.to_num()));
                try!(buffer.write_u16(1));
                try!(buffer.write_u32(ttl));
                try!(buffer.write_u16(4));

                let octets = addr.octets();
                try!(buffer.write_u8(octets[0]));
                try!(buffer.write_u8(octets[1]));
                try!(buffer.write_u8(octets[2]));
                try!(buffer.write_u8(octets[3]));
            },
            DnsRecord::AAAA { ref domain, ref addr, ttl } => {
                try!(buffer.write_qname(domain));
                try!(buffer.write_u16(QueryType::AAAA.to_num()));
                try!(buffer.write_u16(1));
                try!(buffer.write_u32(ttl));
                try!(buffer.write_u16(16));

                for octet in addr.segments().iter() {
                    try!(buffer.write_u16(*octet));
                }
            },
            DnsRecord::NS { ref domain, ref host, ttl } => {
                try!(buffer.write_qname(domain));
                try!(buffer.write_u16(QueryType::NS.to_num()));
                try!(buffer.write_u16(1));
                try!(buffer.write_u32(ttl));

                let pos = buffer.pos();
                try!(buffer.write_u16(0));

                try!(buffer.write_qname(host));

                let size = buffer.pos() - (pos + 2);
                try!(buffer.set_u16(pos, size as u16));
            },
            DnsRecord::CNAME { ref domain, ref host, ttl } => {
                try!(buffer.write_qname(domain));
                try!(buffer.write_u16(QueryType::CNAME.to_num()));
                try!(buffer.write_u16(1));
                try!(buffer.write_u32(ttl));

                let pos = buffer.pos();
                try!(buffer.write_u16(0));

                try!(buffer.write_qname(host));

                let size = buffer.pos() - (pos + 2);
                try!(buffer.set_u16(pos, size as u16));
            },
            DnsRecord::SRV { ref domain, priority, weight, port, ref host, ttl } => {
                try!(buffer.write_qname(domain));
                try!(buffer.write_u16(QueryType::SRV.to_num()));
                try!(buffer.write_u16(1));
                try!(buffer.write_u32(ttl));

                let pos = buffer.pos();
                try!(buffer.write_u16(0));

                try!(buffer.write_u16(priority));
                try!(buffer.write_u16(weight));
                try!(buffer.write_u16(port));
                try!(buffer.write_qname(host));

                let size = buffer.pos() - (pos + 2);
                try!(buffer.set_u16(pos, size as u16));
            },
            DnsRecord::MX { ref domain, priority, ref host, ttl } => {
                try!(buffer.write_qname(domain));
                try!(buffer.write_u16(QueryType::MX.to_num()));
                try!(buffer.write_u16(1));
                try!(buffer.write_u32(ttl));

                let pos = buffer.pos();
                try!(buffer.write_u16(0));

                try!(buffer.write_u16(priority));
                try!(buffer.write_qname(host));

                let size = buffer.pos() - (pos + 2);
                try!(buffer.set_u16(pos, size as u16));
            },
            DnsRecord::SOA {
                ref domain,
                ref mname,
                ref rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
                ttl
            } => {

                try!(buffer.write_qname(domain));
                try!(buffer.write_u16(QueryType::SOA.to_num()));
                try!(buffer.write_u16(1));
                try!(buffer.write_u32(ttl));

                let pos = buffer.pos();
                try!(buffer.write_u16(0));

                try!(buffer.write_qname(mname));
                try!(buffer.write_qname(rname));
                try!(buffer.write_u32(serial));
                try!(buffer.write_u32(refresh));
                try!(buffer.write_u32(retry));
                try!(buffer.write_u32(expire));
                try!(buffer.write_u32(minimum));

                let size = buffer.pos() - (pos + 2);
                try!(buffer.set_u16(pos, size as u16));
            },
            DnsRecord::TXT { ref domain, ref data, ttl } => {
                try!(buffer.write_qname(domain));
                try!(buffer.write_u16(QueryType::TXT.to_num()));
                try!(buffer.write_u16(1));
                try!(buffer.write_u32(ttl));
                try!(buffer.write_u16(data.len() as u16));

                for b in data.as_bytes() {
                    try!(buffer.write_u8(*b));
                }
            },
            DnsRecord::OPT { .. } => {
            },
            DnsRecord::UNKNOWN { .. } => {
                println!("Skipping record: {:?}", self);
            }
        }

        Ok(buffer.pos() - start_pos)
    }

    pub fn get_querytype(&self) -> QueryType {
        match *self {
            DnsRecord::A { .. } => QueryType::A,
            DnsRecord::AAAA { .. } => QueryType::AAAA,
            DnsRecord::NS { .. } => QueryType::NS,
            DnsRecord::CNAME { .. } => QueryType::CNAME,
            DnsRecord::SRV { .. } => QueryType::SRV,
            DnsRecord::MX { .. } => QueryType::MX,
            DnsRecord::UNKNOWN { qtype, .. } => QueryType::UNKNOWN(qtype),
            DnsRecord::SOA { .. } => QueryType::SOA,
            DnsRecord::TXT { .. } => QueryType::TXT,
            DnsRecord::OPT { .. } => QueryType::OPT
        }
    }

    pub fn get_domain(&self) -> Option<String> {
        match *self {
            DnsRecord::A{ ref domain, .. } => Some(domain.clone()),
            DnsRecord::AAAA { ref domain, .. } => Some(domain.clone()),
            DnsRecord::NS { ref domain, .. } => Some(domain.clone()),
            DnsRecord::CNAME { ref domain, .. } => Some(domain.clone()),
            DnsRecord::SRV { ref domain, .. } => Some(domain.clone()),
            DnsRecord::MX { ref domain, .. } => Some(domain.clone()),
            DnsRecord::UNKNOWN { ref domain, .. } => Some(domain.clone()),
            DnsRecord::SOA { ref domain, .. } => Some(domain.clone()),
            DnsRecord::TXT { ref domain, .. } => Some(domain.clone()),
            DnsRecord::OPT { .. } => None
        }
    }

    pub fn get_ttl(&self) -> u32 {
        match *self {
            DnsRecord::A { ttl, .. } => ttl,
            DnsRecord::AAAA { ttl, .. } => ttl,
            DnsRecord::NS { ttl, .. } => ttl,
            DnsRecord::CNAME { ttl, .. } => ttl,
            DnsRecord::SRV { ttl, .. } => ttl,
            DnsRecord::MX { ttl, .. } => ttl,
            DnsRecord::UNKNOWN { ttl, .. } => ttl,
            DnsRecord::SOA { ttl, .. } => ttl,
            DnsRecord::TXT { ttl, .. } => ttl,
            DnsRecord::OPT { .. } => 0
        }
    }
}

/// The result code for a DNS query, as described in the specification
#[derive(Clone,Debug,PartialEq,Eq)]
pub enum ResultCode {
    NOERROR = 0,
    FORMERR = 1,
    SERVFAIL = 2,
    NXDOMAIN = 3,
    NOTIMP = 4,
    REFUSED = 5
}

impl ResultCode {
    pub fn from_num(num: u8) -> ResultCode {
        match num {
            0 => ResultCode::NOERROR,
            1 => ResultCode::FORMERR,
            2 => ResultCode::SERVFAIL,
            3 => ResultCode::NXDOMAIN,
            4 => ResultCode::NOTIMP,
            5 => ResultCode::REFUSED,
            _ => ResultCode::NOERROR
        }
    }
}

/// Representation of a DNS header
#[derive(Clone,Debug)]
pub struct DnsHeader {
    pub id: u16, // 16 bits

    pub recursion_desired: bool, // 1 bit
    pub truncated_message: bool, // 1 bit
    pub authoritative_answer: bool, // 1 bit
    pub opcode: u8, // 4 bits
    pub response: bool, // 1 bit

    pub rescode: ResultCode, // 4 bits
    pub checking_disabled: bool, // 1 bit
    pub authed_data: bool, // 1 bit
    pub z: bool, // 1 bit
    pub recursion_available: bool, // 1 bit

    pub questions: u16, // 16 bits
    pub answers: u16, // 16 bits
    pub authoritative_entries: u16, // 16 bits
    pub resource_entries: u16 // 16 bits
}

impl DnsHeader {
    pub fn new() -> DnsHeader {
        DnsHeader { id: 0,

                    recursion_desired: false,
                    truncated_message: false,
                    authoritative_answer: false,
                    opcode: 0,
                    response: false,

                    rescode: ResultCode::NOERROR,
                    checking_disabled: false,
                    authed_data: false,
                    z: false,
                    recursion_available: false,

                    questions: 0,
                    answers: 0,
                    authoritative_entries: 0,
                    resource_entries: 0 }
    }

    pub fn write<T: PacketBuffer>(&self, buffer: &mut T) -> Result<()> {
        try!(buffer.write_u16(self.id));

        try!(buffer.write_u8( ((self.recursion_desired as u8)) |
                              ((self.truncated_message as u8) << 1) |
                              ((self.authoritative_answer as u8) << 2) |
                              (self.opcode << 3) |
                              ((self.response as u8) << 7) as u8) );

        try!(buffer.write_u8( (self.rescode.clone() as u8) |
                              ((self.checking_disabled as u8) << 4) |
                              ((self.authed_data as u8) << 5) |
                              ((self.z as u8) << 6) |
                              ((self.recursion_available as u8) << 7) ));

        try!(buffer.write_u16(self.questions));
        try!(buffer.write_u16(self.answers));
        try!(buffer.write_u16(self.authoritative_entries));
        try!(buffer.write_u16(self.resource_entries));

        Ok(())
    }

    pub fn binary_len(&self) -> usize {
        12
    }

    pub fn read<T: PacketBuffer>(&mut self, buffer: &mut T) -> Result<()> {
        self.id = try!(buffer.read_u16());

        let flags = try!(buffer.read_u16());
        let a = (flags >> 8) as u8;
        let b = (flags & 0xFF) as u8;
        self.recursion_desired = (a & (1 << 0)) > 0;
        self.truncated_message = (a & (1 << 1)) > 0;
        self.authoritative_answer = (a & (1 << 2)) > 0;
        self.opcode = (a >> 3) & 0x0F;
        self.response = (a & (1 << 7)) > 0;

        self.rescode = ResultCode::from_num(b & 0x0F);
        self.checking_disabled = (b & (1 << 4)) > 0;
        self.authed_data = (b & (1 << 5)) > 0;
        self.z = (b & (1 << 6)) > 0;
        self.recursion_available = (b & (1 << 7)) > 0;

        self.questions = try!(buffer.read_u16());
        self.answers = try!(buffer.read_u16());
        self.authoritative_entries = try!(buffer.read_u16());
        self.resource_entries = try!(buffer.read_u16());

        // Return the constant header size
        Ok(())
    }
}

impl fmt::Display for DnsHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        try!(write!(f, "DnsHeader:\n"));
        try!(write!(f, "\tid: {0}\n", self.id));

        try!(write!(f, "\trecursion_desired: {0}\n", self.recursion_desired));
        try!(write!(f, "\ttruncated_message: {0}\n", self.truncated_message));
        try!(write!(f, "\tauthoritative_answer: {0}\n", self.authoritative_answer));
        try!(write!(f, "\topcode: {0}\n", self.opcode));
        try!(write!(f, "\tresponse: {0}\n", self.response));

        try!(write!(f, "\trescode: {:?}\n", self.rescode));
        try!(write!(f, "\tchecking_disabled: {0}\n", self.checking_disabled));
        try!(write!(f, "\tauthed_data: {0}\n", self.authed_data));
        try!(write!(f, "\tz: {0}\n", self.z));
        try!(write!(f, "\trecursion_available: {0}\n", self.recursion_available));

        try!(write!(f, "\tquestions: {0}\n", self.questions));
        try!(write!(f, "\tanswers: {0}\n", self.answers));
        try!(write!(f, "\tauthoritative_entries: {0}\n", self.authoritative_entries));
        try!(write!(f, "\tresource_entries: {0}\n", self.resource_entries));

        Ok(())
    }
}

/// Representation of a DNS question
#[derive(Debug,Clone,PartialEq,Eq)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: QueryType
}

impl DnsQuestion {
    pub fn new(name: &String, qtype: QueryType) -> DnsQuestion {
        DnsQuestion {
            name: name.to_string(),
            qtype: qtype
        }
    }

    pub fn binary_len<T: PacketBuffer>(&self, buffer: &T) -> usize {
        buffer.qname_len(&self.name) + 4
    }

    pub fn write<T: PacketBuffer>(&self, buffer: &mut T) -> Result<()> {

        try!(buffer.write_qname(&self.name));

        let typenum = self.qtype.to_num();
        try!(buffer.write_u16(typenum));
        try!(buffer.write_u16(1));

        Ok(())
    }

    pub fn read<T: PacketBuffer>(&mut self, buffer: &mut T) -> Result<()> {
        let _ = buffer.read_qname(&mut self.name);
        self.qtype = QueryType::from_num(try!(buffer.read_u16())); // qtype
        let _ = buffer.read_u16(); // class

        Ok(())
    }
}

impl fmt::Display for DnsQuestion {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        try!(write!(f, "DnsQuestion:\n"));
        try!(write!(f, "\tname: {0}\n", self.name));
        try!(write!(f, "\trecord type: {:?}\n", self.qtype));

        Ok(())
    }
}

/// Representation of a complete DNS packet
///
/// This is the work horse of the server. A DNS packet can be read and written
/// in a single operation, and is used both by the network facing components and
/// internally by the resolver, cache and authority.
#[derive(Clone, Debug)]
pub struct DnsPacket {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub resources: Vec<DnsRecord>
}

impl DnsPacket {
    pub fn new() -> DnsPacket {
        DnsPacket {
            header: DnsHeader::new(),
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            resources: Vec::new()
        }
    }

    pub fn from_buffer<T: PacketBuffer>(buffer: &mut T) -> Result<DnsPacket> {
        let mut result = DnsPacket::new();
        try!(result.header.read(buffer));

        for _ in 0..result.header.questions {
            let mut question = DnsQuestion::new(&"".to_string(),
                                                QueryType::UNKNOWN(0));
            try!(question.read(buffer));
            result.questions.push(question);
        }

        for _ in 0..result.header.answers {
            let rec = try!(DnsRecord::read(buffer));
            result.answers.push(rec);
        }
        for _ in 0..result.header.authoritative_entries {
            let rec = try!(DnsRecord::read(buffer));
            result.authorities.push(rec);
        }
        for _ in 0..result.header.resource_entries {
            let rec = try!(DnsRecord::read(buffer));
            result.resources.push(rec);
        }

        Ok(result)
    }

    #[allow(dead_code)]
    pub fn print(&self) {
        //println!("query domain: {0}", self.domain);

        println!("answers:");
        for x in &self.answers {
            println!("\t{:?}", x);
        }

        println!("authorities:");
        for x in &self.authorities {
            println!("\t{:?}", x);
        }

        println!("resources:");
        for x in &self.resources {
            println!("\t{:?}", x);
        }
    }

    pub fn get_ttl_from_soa(&self) -> Option<u32> {
        for answer in &self.authorities {
            if let DnsRecord::SOA { retry, .. } = *answer {
                return Some(retry);
            }
        }

        None
    }

    pub fn get_random_a(&self) -> Option<String> {
        if self.answers.len() > 0 {
            let idx = random::<usize>() % self.answers.len();
            let a_record = &self.answers[idx];
            if let &DnsRecord::A{ ref addr, .. } = a_record {
                return Some(addr.to_string());
            }
        }

        None
    }

    pub fn get_unresolved_cnames(&self) -> Vec<DnsRecord> {

        let mut unresolved = Vec::new();
        for answer in &self.answers {
            let mut matched = false;
            if let DnsRecord::CNAME { ref host, .. } = *answer {
                for answer2 in &self.answers {
                    if let DnsRecord::A { ref domain, .. } = *answer2 {
                        if domain == host {
                            matched = true;
                            break;
                        }
                    }
                }
            }

            if !matched {
                unresolved.push(answer.clone());
            }
        }

        unresolved
    }

    pub fn get_resolved_ns(&self, qname: &str) -> Option<String> {

        let mut new_authorities = Vec::new();
        for auth in &self.authorities {
            if let DnsRecord::NS { ref domain, ref host, .. } = *auth {
                if !qname.ends_with(domain) {
                    continue;
                }

                for rsrc in &self.resources {
                    if let DnsRecord::A{ ref domain, ref addr, ref ttl } = *rsrc {
                        if domain != host {
                            continue;
                        }

                        let rec = DnsRecord::A {
                            domain: host.clone(),
                            addr: addr.clone(),
                            ttl: *ttl
                        };

                        new_authorities.push(rec);
                    }
                }
            }
        }

        if new_authorities.len() > 0 {
            let idx = random::<usize>() % new_authorities.len();
            if let DnsRecord::A { addr, .. } = new_authorities[idx] {
                return Some(addr.to_string());
            }
        }

        None
    }

    pub fn get_unresolved_ns(&self, qname: &str) -> Option<String> {

        let mut new_authorities = Vec::new();
        for auth in &self.authorities {
            if let DnsRecord::NS { ref domain, ref host, .. } = *auth {
                if !qname.ends_with(domain) {
                    continue;
                }

                new_authorities.push(host);
            }
        }

        if new_authorities.len() > 0 {
            let idx = random::<usize>() % new_authorities.len();
            return Some(new_authorities[idx].clone());
        }

        None
    }

    pub fn write<T: PacketBuffer>(&mut self,
                                  buffer: &mut T,
                                  max_size: usize) -> Result<()>
    {
        let mut test_buffer = VectorPacketBuffer::new();

        let mut size = self.header.binary_len();
        for ref question in &self.questions {
            size += question.binary_len(buffer);
            try!(question.write(&mut test_buffer));
        }

        let mut record_count = self.answers.len() + self.authorities.len() + self.resources.len();

        for (i, rec) in self.answers.iter().chain(self.authorities.iter()).chain(self.resources.iter()).enumerate() {
            size += try!(rec.write(&mut test_buffer));
            if size > max_size {
                record_count = i;
                self.header.truncated_message = true;
                break;
            } else if i < self.answers.len() {
                self.header.answers += 1;
            } else if i < self.answers.len() + self.authorities.len() {
                self.header.authoritative_entries += 1;
            } else {
                self.header.resource_entries += 1;
            }
        }

        self.header.questions = self.questions.len() as u16;

        try!(self.header.write(buffer));

        for question in &self.questions {
            try!(question.write(buffer));
        }

        for rec in self.answers.iter().chain(self.authorities.iter()).chain(self.resources.iter()).take(record_count) {
            try!(rec.write(buffer));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use std::net::Ipv4Addr;
    use dns::buffer::{PacketBuffer, VectorPacketBuffer};

    #[test]
    fn test_packet() {
        let mut packet = DnsPacket::new();
        packet.header.id = 1337;
        packet.header.response = true;

        packet.questions.push(DnsQuestion::new(&"google.com".to_string(), QueryType::NS));
        //packet.answers.push(DnsRecord::A("ns1.google.com".to_string(), "127.0.0.1".parse::<Ipv4Addr>().unwrap(), 3600));
        packet.answers.push(DnsRecord::NS {
            domain: "google.com".to_string(),
            host: "ns1.google.com".to_string(),
            ttl: 3600
        });
        packet.answers.push(DnsRecord::NS {
            domain: "google.com".to_string(),
            host: "ns2.google.com".to_string(),
            ttl: 3600
        });
        packet.answers.push(DnsRecord::NS {
            domain: "google.com".to_string(),
            host: "ns3.google.com".to_string(),
            ttl: 3600
        });
        packet.answers.push(DnsRecord::NS {
            domain: "google.com".to_string(),
            host: "ns4.google.com".to_string(),
            ttl: 3600
        });

        let mut buffer = VectorPacketBuffer::new();
        packet.write(&mut buffer, 0xFFFF).unwrap();

        buffer.seek(0).unwrap();

        let parsed_packet = DnsPacket::from_buffer(&mut buffer).unwrap();

        assert_eq!(packet.questions[0], parsed_packet.questions[0]);
        assert_eq!(packet.answers[0], parsed_packet.answers[0]);
        assert_eq!(packet.answers[1], parsed_packet.answers[1]);
        assert_eq!(packet.answers[2], parsed_packet.answers[2]);
        assert_eq!(packet.answers[3], parsed_packet.answers[3]);
    }
}
