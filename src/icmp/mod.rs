use crate::util::checksum::csum16;

pub const ICMP_ECHO_REQUEST: u8 = 8;
pub const ICMP_ECHO_REPLY:   u8 = 0;

pub fn build_echo_reply(id: u16, seq: u16, data: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(8 + data.len());
    p.push(ICMP_ECHO_REPLY);
    p.push(0); // code
    p.extend_from_slice(&[0,0]); // checksum placeholder
    p.extend_from_slice(&id.to_be_bytes());
    p.extend_from_slice(&seq.to_be_bytes());
    p.extend_from_slice(data);
    let c = csum16(&p);
    p[2] = (c >> 8) as u8;
    p[3] = (c & 0xff) as u8;
    p
}

pub fn parse_echo(pkt: &[u8]) -> Option<(u16,u16,&[u8])> {
    if pkt.len() < 8 { return None; }
    if pkt[0] != ICMP_ECHO_REQUEST { return None; }
    let id = u16::from_be_bytes([pkt[4], pkt[5]]);
    let seq= u16::from_be_bytes([pkt[6], pkt[7]]);
    Some((id, seq, &pkt[8..]))
}
