use std::fs::File;
use std::io::BufReader;
use std::io::BufRead;
use std::path::Path;
use std::collections::HashSet;
use dns::protocol::DnsPacket;
use dns::protocol::DnsRecord;
use dns::protocol::TransientTtl;
use dns::protocol::ResultCode;
use dns::utils::current_time_millis;

static SOA_FAKE_DOMAIN: &str = "fake-for-negative-caching.adguard.com.";
static NEGATIVE_TTL: u32 = 900;
static REFRESH_TIME: u32 = 1800;
static EXPIRE_TIME: u32 = 604800;
static MINIMUM_TIME: u32 = 86400;

pub struct DnsFilter {
    blocked: HashSet<String>
}

impl DnsFilter {
    pub fn new() -> DnsFilter {
        DnsFilter {
            blocked: HashSet::new()
        }
    }

    pub fn load_rules(&mut self, path: &Path) {
        // let path = Path::new("./foo/bar.txt");
        let file = File::open(path);

        match file {
            Ok(f) => {
                let mut reader = BufReader::new(f);

                for line in reader.lines() {
                    let l = line.unwrap();
                    self.add_rule(l);
                }
            },
            Err(text) => {
                println!("Error opening filter file: {:?} ({})", path, text);
            }
        }
    }

    pub fn contains(&self, domain: &str) -> bool {
        return self.blocked.contains(domain);
    }

    pub fn fill_blocked_response(request: &mut DnsPacket) {
        request.header.res_code = ResultCode::NXDOMAIN;
        let question = &request.questions[0];
        let mut domain = question.name.clone();
        if domain.ends_with(".") {
            domain = (&domain[..domain.len()-1]).to_owned();
        }
        let pos = match domain.rfind(".") {
            Some(x) => x,
            None => 0
        };

        if pos > 0 {
            domain = (&domain[pos..]).to_owned();
        }

        let record = DnsRecord::SOA {
            domain,
            m_name: SOA_FAKE_DOMAIN.to_owned(),
            r_name: SOA_FAKE_DOMAIN.to_owned(),
            serial: current_time_millis() as u32,
            refresh: REFRESH_TIME,
            retry: NEGATIVE_TTL,
            expire: EXPIRE_TIME,
            minimum: MINIMUM_TIME,
            ttl: TransientTtl(NEGATIVE_TTL),
        };

        request.authorities.push(record);
    }

    fn add_rule(&mut self, rule: String) {
        if rule.starts_with("!") {
            return;
        }

        let mut line = rule.clone();

        if line.starts_with("||") {
            line = (&line[2..]).to_string();
        }

        if line.ends_with("^") || line.ends_with("/") {
            line = (&line[0..line.len() - 1]).to_string();
        }

        if line.starts_with("http://") {
            line = (&line[7..]).to_string();
        }

        if line.starts_with("/") || line.ends_with(".js") || line.starts_with("@@") {
            return;
        }

        println!("Rule {} -> {}", rule, line);
        self.blocked.insert(line);
    }
}