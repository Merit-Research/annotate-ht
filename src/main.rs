use csv::ReaderBuilder;
use hex;
use std::error::Error;
use std::fs::File;
use std::io::{Error as IoError, ErrorKind};

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: {} <input.csv> <output.csv>", args[0]);
        std::process::exit(1);
    }
    let file = File::open(&args[1])?;
    let mut rdr = ReaderBuilder::new().has_headers(true).from_reader(file);
    let mut wtr = csv::Writer::from_path(&args[2])?;

    let headers = rdr.headers()?.clone();
    let mut new_headers = headers.iter().map(|s| s.to_owned()).collect::<Vec<_>>();
    new_headers.push("Payload Type".to_string());
    wtr.write_record(&new_headers)?;

    for result in rdr.records() {
        let record = result?;
        let mut new_record = record.iter().map(|s| s.to_owned()).collect::<Vec<_>>();

        // Assuming the 6th column (index 5) contains the hex payload
        if let Some(payload_hex) = record.get(5) {
            let payload_bytes = hex::decode(payload_hex).map_err(|e| {
                IoError::new(
                    ErrorKind::InvalidData,
                    format!("Failed to decode hex string: {}", e),
                )
            })?;

            match detect_payload_type(&payload_bytes) {
                Some(payload_type) => new_record.push(format!("{:?}", payload_type)),
                None => new_record.push(format!("Error: {}", "Failed to detect payload type")),
            }
        } else {
            new_record.push("Missing Payload".to_string());
        }

        wtr.write_record(&new_record)?;
    }

    wtr.flush()?;
    Ok(())
}

#[derive(Debug, PartialEq)]
enum PayloadType {
    DNS,
    HTTP,
    SMTP,
    FTP,
    SSH,
    TLS,
    POP3,
    IMAP,
    Telnet,
    SMB,
    DHCP,
    NTP,
    SNMP,
    Unknown,
    NoData,
}

fn check_dns_domain(payload: &[u8], mut offset: usize) -> Option<usize> {
    let mut domain_name = String::new();

    while offset < payload.len() {
        let label_len = payload[offset] as usize;

        if (label_len & 0xc0) == 0xc0 {
            if offset + 1 >= payload.len() {
                return None;
            }

            let pointer = ((label_len as u16 & 0x3f) << 8) | payload[offset + 1] as u16;
            offset = pointer as usize;
            break;
        }

        if label_len == 0 {
            offset += 1;
            break;
        }

        offset += 1;

        if offset + label_len > payload.len() {
            // invalid question
            return None;
        }

        let label = &payload[offset..offset + label_len];
        domain_name.push_str(&String::from_utf8_lossy(label));
        domain_name.push('.');

        offset += label_len;
    }

    Some(offset)
}

// possibly incomplete list of DNS types
const DNS_TYPES: [u16; 82] = [
    1, // A
    2, // NS
    3, // MD
    4, // MF
    5, // CNAME
    6, // SOA
    7, // MB
    8, // MG
    9, // MR
    10, // NULL
    11, // WKS
    12, // PTR
    13, // HINFO
    14, // MINFO
    15, // MX
    16, // TXT
    17, // RP
    18, // AFSDB
    19, // X25
    20, // ISDN
    21, // RT
    22, // NSAP
    23, // NSAP-PTR
    24, // SIG
    25, // KEY
    26, // PX
    27, // GPOS
    28, // AAAA
    29, // LOC
    30, // NXT
    31, // EID
    32, // NIMLOC
    33, // SRV
    34, // ATMA
    35, // NAPTR
    36, // KX
    37, // CERT
    38, // A6
    39, // DNAME
    40, // SINK
    42, // APL
    43, // DS
    44, // SSHFP
    45, // IPSECKEY
    46, // RRSIG
    47, // NSEC
    48, // DNSKEY
    49, // DHCID
    50, // NSEC3
    51, // NSEC3PARAM
    52, // TLSA
    55, // HIP
    56, // NINFO
    57, // RKEY
    58, // TALINK
    59, // CDS
    60, // CDNSKEY
    61, // OPENPGPKEY
    62, // CSYNC
    63, // ZONEMD
    64, // SVCB
    65, // HTTPS
    99, // SPF
    100, // UINFO
    101, // UID
    102, // GID
    103, // UNSPEC
    104, // NID
    105, // L32
    106, // L64
    107, // LP
    108, // EUI48
    109, // EUI64
    249, // TKEY
    250, // TSIG
    253, // MAILB
    254, // MAILA
    256, // URI
    257, // CAA
    259, // DOA
    32768, // TA
    32769, // DLV

];

fn validate_resource_record(payload: &[u8], mut offset: usize) -> Option<usize> {
    offset = match check_dns_domain(payload, offset) {
        Some(o) => o,
        None => return None,
    };

    if offset + 10 > payload.len() {
        return None;
    }

    let rtype = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
    // let rclass = u16::from_be_bytes([payload[offset + 2], payload[offset + 3]]);
    // let ttl = u32::from_be_bytes([
    //     payload[offset + 4],
    //     payload[offset + 5],
    //     payload[offset + 6],
    //     payload[offset + 7],
    // ]);
    let rdlength = u16::from_be_bytes([payload[offset + 8], payload[offset + 9]]);

    offset += 10; // Skip fixed-size fields

    // Add RDATA validation based on rtype
    match rtype {
        1 => {
            // A record: 4 bytes for IPv4 address
            if offset + 4 > payload.len() {
                return None;
            }
            // You can add more specific validation for the IPv4 address here
            offset += 4;
        }
        28 => {
            // AAAA record: 16 bytes for IPv6 address
            if offset + 16 > payload.len() {
                return None;
            }
            // You can add more specific validation for the IPv6 address here
            offset += 16;
        }
        // Add more cases for other RTYPEs as needed...
        _ => {
            // For other types, you might need to parse and validate the RDATA
            // based on the specific RTYPE and its format
            offset += rdlength as usize;
        }
    }

    if offset > payload.len() {
        return None;
    }

    Some(offset)
}

fn check_dns(payload: &[u8]) -> bool {
    // dns MUST be at least 12 bytes
    if payload.len() < 12 {
        return false;
    }

    // let transaction_id = u16::from_be_bytes([payload[0], payload[1]]);
    // let flags = u16::from_be_bytes([payload[2], payload[3]]);
    let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
    let ancount = u16::from_be_bytes([payload[6], payload[7]]);
    let nscount = u16::from_be_bytes([payload[8], payload[9]]);
    let arcount = u16::from_be_bytes([payload[10], payload[11]]);

    if qdcount == 0 {
        // no questions were asked, this would be very unusual for a DNS packet
        return false;
    }

    // Check for valid DNS query/response types and classes
    let mut offset = 12;
    for _ in 0..qdcount {
        offset = match check_dns_domain(payload, offset) {
            Some(o) => o,
            None => return false,
        };

        if offset + 4 > payload.len() {
            return false;
        }

        let qtype = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
        //let qclass = u16::from_be_bytes([payload[offset + 2], payload[offset + 3]]);

        offset += 4;

        if ! DNS_TYPES.contains(&qtype) {
            return false;
        }

    }

    for _ in 0..ancount {
        offset = match validate_resource_record(payload, offset) {
            Some(o) => o,
            None => return false,
        };
    }

    for _ in 0..nscount {
        offset = match validate_resource_record(payload, offset) {
            Some(o) => o,
            None => return false,
        };
    }

    for _ in 0..arcount {
        offset = match validate_resource_record(payload, offset) {
            Some(o) => o,
            None => return false,
        };
    }

    //println!("DNS packet detected with {} questions, {} answers, {} authorities, and {} additionals", qdcount, ancount, nscount, arcount);

    true
}

fn check_dhcp(payload: &[u8]) -> bool {
    // Minimum length for a DHCP packet (BOOTP header + magic cookie)
    if payload.len() < 240 {
        return false;
    }

    // Validate BOOTP message type
    let bootp_message_type = payload[0];
    if bootp_message_type != 1 && bootp_message_type != 2 {
        return false;
    }

    // Check for DHCP magic cookie (0x63, 0x82, 0x53, 0x63)
    if &payload[236..240] != [0x63, 0x82, 0x53, 0x63] {
        return false;
    }

    // Parse and validate DHCP options
    let mut offset = 240;
    while offset < payload.len() {
        let option_type = payload[offset];
        if option_type == 255 {
            // End option
            break;
        }

        if offset + 1 >= payload.len() {
            return false;
        }

        let option_length = payload[offset + 1] as usize;
        offset += 2;

        if offset + option_length > payload.len() {
            return false;
        }

        // Validate specific options if needed
        // For example, check DHCP message type option (53)
        if option_type == 53 && option_length == 1 {
            let dhcp_message_type = payload[offset];
            if dhcp_message_type < 1 || dhcp_message_type > 8 {
                return false;
            }
        }

        offset += option_length;
    }

    true
}

fn check_ntp(payload: &[u8]) -> bool {
    // Minimum length for an NTP packet
    if payload.len() < 48 {
        return false;
    }

    // Validate the first byte (LI, VN, Mode)
    let leap_indicator = payload[0] >> 6;
    let version_number = (payload[0] >> 3) & 0b00000111;
    let mode = payload[0] & 0b00000111;

    // Leap Indicator should be between 0 and 3
    if leap_indicator > 3 {
        return false;
    }

    // Version Number should be between 1 and 4 (NTPv1 to NTPv4)
    if version_number < 1 || version_number > 4 {
        return false;
    }

    // Mode should be between 1 and 5 (symmetric active, symmetric passive, client, server, broadcast)
    if mode < 1 || mode > 5 {
        return false;
    }

    // Validate the stratum (should be between 0 and 15)
    let stratum = payload[1];
    if stratum > 15 {
        return false;
    }

    // Validate the poll interval (should be between 4 and 17)
    let poll_interval = payload[2];
    if poll_interval < 4 || poll_interval > 17 {
        return false;
    }

    // Validate the precision (should be a signed byte, typically between -6 and -20)
    let precision = payload[3] as i8;
    if precision > -6 || precision < -20 {
        return false;
    }

    // Validate the root delay and root dispersion (should be non-negative)
    let root_delay = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
    let root_dispersion = u32::from_be_bytes([payload[8], payload[9], payload[10], payload[11]]);
    if root_delay & 0x80000000 != 0 || root_dispersion & 0x80000000 != 0 {
        return false;
    }

    // Validate the reference identifier (should be non-zero)
    let reference_identifier = &payload[12..16];
    if reference_identifier == &[0, 0, 0, 0] {
        return false;
    }

    // Validate the timestamps (should be non-zero)
    let reference_timestamp = &payload[16..24];
    let originate_timestamp = &payload[24..32];
    let receive_timestamp = &payload[32..40];
    let transmit_timestamp = &payload[40..48];
    if reference_timestamp == &[0, 0, 0, 0, 0, 0, 0, 0]
        || originate_timestamp == &[0, 0, 0, 0, 0, 0, 0, 0]
        || receive_timestamp == &[0, 0, 0, 0, 0, 0, 0, 0]
        || transmit_timestamp == &[0, 0, 0, 0, 0, 0, 0, 0]
    {
        return false;
    }

    true
}

fn check_snmp(payload: &[u8]) -> bool {
    // Minimum length for an SNMP packet
    if payload.len() < 2 {
        return false;
    }

    // Check SNMP version (0 for SNMPv1, 1 for SNMPv2c)
    let version = payload[0];
    if version != 0 && version != 1 {
        return false;
    }

    // Check for community string (at least 1 byte)
    let community_length = payload[1] as usize;
    if community_length == 0 || 2 + community_length > payload.len() {
        return false;
    }

    // Check for PDU type (GetRequest, GetNextRequest, GetResponse, SetRequest, etc.)
    if 2 + community_length >= payload.len() {
        return false;
    }
    let pdu_type = payload[2 + community_length];
    if pdu_type < 0xA0 || pdu_type > 0xA3 {
        return false;
    }

    true
}

fn check_telnet(payload: &[u8]) -> bool {
    // Telnet commands are at least 2 bytes long and start with 0xFF (IAC - Interpret As Command)
    if payload.len() < 2 {
        return false;
    }

    let mut i = 0;
    while i < payload.len() {
        if payload[i] == 0xFF {
            // IAC command
            if i + 1 >= payload.len() {
                return false;
            }

            match payload[i + 1] {
                0xF0..=0xF9 | 0xFB..=0xFE => {
                    // Single byte commands (IAC SE, NOP, Data Mark, Break, IP, AO, AYT, EC, EL, GA, SB, WILL, WONT, DO, DONT)
                    i += 2;
                }
                0xFA => {
                    // IAC SB (Subnegotiation) command
                    i += 2;
                    while i < payload.len() && payload[i] != 0xFF {
                        i += 1;
                    }
                    if i + 1 >= payload.len() || payload[i + 1] != 0xF0 {
                        return false;
                    }
                    i += 2;
                }
                _ => {
                    return false;
                }
            }
        } else {
            // Regular data byte
            i += 1;
        }
    }

    true
}

fn check_http(payload: &[u8]) -> bool {
    // HTTP methods
    let methods: Vec<&[u8]> = vec![
        b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"CONNECT ", b"TRACE ", b"PATCH "
    ];

    // Check if the payload starts with any of the HTTP methods
    for method in methods {
        if payload.starts_with(method) {
            return true;
        }
    }

    // Check for HTTP response status line (e.g., "HTTP/1.1 200 OK")
    if payload.starts_with(b"HTTP/1.0 ") || payload.starts_with(b"HTTP/1.1 ") || payload.starts_with(b"HTTP/2 ") {
        return true;
    }

    false
}

fn detect_payload_type(payload: &[u8]) -> Option<PayloadType> {
    // empty
    if payload.len() == 0 {
        return Some(PayloadType::NoData);
    }

    // dns
    if check_dns(payload) {
        return Some(PayloadType::DNS);
    }

    // crude dhcp detection
    if check_dhcp(payload) {
        return Some(PayloadType::DHCP);
    }

    // ntp
    if check_ntp(payload) {
        return Some(PayloadType::NTP);
    }

    // snmp
    if check_snmp(payload) {
        return Some(PayloadType::SNMP);
    }

    // http
    if check_http(payload) {
        return Some(PayloadType::HTTP);
    }

    // smtp
    if payload.starts_with(b"EHLO ")
        || payload.starts_with(b"HELO ")
        || payload.starts_with(b"MAIL FROM:")
        || payload.starts_with(b"RCPT TO:")
        || payload.starts_with(b"DATA")
        || payload.starts_with(b"QUIT")
    {
        return Some(PayloadType::SMTP);
    }

    // ftp
    if payload.starts_with(b"USER ")
        || payload.starts_with(b"PASS ")
        || payload.starts_with(b"STOR ")
        || payload.starts_with(b"RETR ")
        || payload.starts_with(b"LIST")
        || payload.starts_with(b"QUIT")
    {
        return Some(PayloadType::FTP);
    }

    // ssh
    if payload.starts_with(b"SSH-") {
        return Some(PayloadType::SSH);
    }

    // basic tls handshake detection
    if payload.len() >= 5 && payload[0] == 0x16 && payload[1] == 0x03 {
        return Some(PayloadType::TLS);
    }

    // pop3
    if payload.starts_with(b"+OK ") || payload.starts_with(b"-ERR ") {
        return Some(PayloadType::POP3);
    }

    // imap
    if payload.starts_with(b"* OK ")
        || payload.starts_with(b"* BYE ")
        || payload.starts_with(b"* CAPABILITY ")
    {
        return Some(PayloadType::IMAP);
    }

    // telnet
    if check_telnet(payload) {
        return Some(PayloadType::Telnet);
    }

    // SMB
    if payload.starts_with(b"\xff\x53\x4d\x42") {
        return Some(PayloadType::SMB);
    }

    Some(PayloadType::Unknown)
}

