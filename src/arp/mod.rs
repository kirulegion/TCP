use crate::l2::ethernet::{Mac, ETH_P_ARP};
use std::time::{Instant, Duration};

const HTYPE_ETH: u16 = 1;
const PTYPE_IPV4: u16 = 0x0800;
const HLEN_ETH:  u8 = 6;
const PLEN_IPV4: u8 = 4;
const OPCODE_REQUEST: u16 = 1;
const OPCODE_REPLY:   u16 = 2;

#[derive(Clone, Copy)]
pub struct Ipv4(pub [u8;4]);

impl Ipv4 {
    pub fn parse(s: &str) -> Self {
        let mut a = [0u8;4];
        for (i, part) in s.split('.').enumerate() {
            a[i] = part.parse::<u8>().unwrap();
        }
        Ipv4(a)
    }
}

#[derive(Clone)]
pub struct ArpEntry {
    pub ip: Ipv4,
    pub mac: Mac,
    pub updated: Instant,
}

pub struct ArpCache {
    pub our_ip: Ipv4,
    pub our_mac: Mac,
    pub entries: Vec<ArpEntry>,
}

impl ArpCache {
    pub fn new(our_ip: Ipv4, our_mac: Mac) -> Self {
        Self { our_ip, our_mac, entries: Vec::new() }
    }
    pub fn lookup(&self, ip: Ipv4) -> Option<Mac> {
        self.entries.iter().find(|e| e.ip.0 == ip.0).map(|e| e.mac)
    }
    pub fn insert(&mut self, ip: Ipv4, mac: Mac) {
        if let Some(e) = self.entries.iter_mut().find(|e| e.ip.0 == ip.0) {
            e.mac = mac; e.updated = Instant::now();
        } else {
            self.entries.push(ArpEntry{ ip, mac, updated: Instant::now() });
        }
    }

    pub fn gc(&mut self) {
        let ttl = Duration::from_secs(60);
        self.entries.retain(|e| e.updated.elapsed() < ttl);
    }
}

pub fn build_request(our_mac: Mac, our_ip: Ipv4, target_ip: Ipv4) -> Vec<u8> {
    let mut p = Vec::with_capacity(28);
    p.extend_from_slice(&HTYPE_ETH.to_be_bytes());
    p.extend_from_slice(&PTYPE_IPV4.to_be_bytes());
    p.push(HLEN_ETH);
    p.push(PLEN_IPV4);
    p.extend_from_slice(&OPCODE_REQUEST.to_be_bytes());
    p.extend_from_slice(&our_mac.0);
    p.extend_from_slice(&our_ip.0);
    p.extend_from_slice(&[0u8;6]);
    p.extend_from_slice(&target_ip.0);
    p
}

pub fn build_reply(our_mac: Mac, our_ip: Ipv4, dst_mac: Mac, dst_ip: Ipv4) -> Vec<u8> {
    let mut p = Vec::with_capacity(28);
    p.extend_from_slice(&HTYPE_ETH.to_be_bytes());
    p.extend_from_slice(&PTYPE_IPV4.to_be_bytes());
    p.push(HLEN_ETH);
    p.push(PLEN_IPV4);
    p.extend_from_slice(&OPCODE_REPLY.to_be_bytes());
    p.extend_from_slice(&our_mac.0);
    p.extend_from_slice(&our_ip.0);
    p.extend_from_slice(&dst_mac.0);
    p.extend_from_slice(&dst_ip.0);
    p
}

pub fn parse(packet: &[u8]) -> Option<(u16, Mac, Ipv4, Mac, Ipv4)> {
    if packet.len() < 28 { return None; }
    let op = u16::from_be_bytes([packet[6], packet[7]]);
    let smac = Mac([packet[8],packet[9],packet[10],packet[11],packet[12],packet[13]]);
    let sip  = Ipv4([packet[14],packet[15],packet[16],packet[17]]);
    let tmac = Mac([packet[18],packet[19],packet[20],packet[21],packet[22],packet[23]]);
    let tip  = Ipv4([packet[24],packet[25],packet[26],packet[27]]);
    Some((op, smac, sip, tmac, tip))
}
