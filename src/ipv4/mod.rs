use crate::util::checksum::csum16;

pub const IP_PROTO_ICMP: u8 = 1;
pub const IP_PROTO_TCP:  u8 = 6;

#[derive(Clone, Copy)]
pub struct Ipv4Hdr {
    pub tos: u8,
    pub id: u16,
    pub flags_frag: u16,
    pub ttl: u8,
    pub proto: u8,
    pub src: [u8;4],
    pub dst: [u8;4],
}

impl Ipv4Hdr {
    pub fn serialize(&self, payload: &[u8], out: &mut Vec<u8>) {
        let ihl_ver = (4u8 << 4) | 5;
        let tot_len = (20 + payload.len()) as u16;
        out.push(ihl_ver);
        out.push(self.tos);
        out.extend_from_slice(&tot_len.to_be_bytes());
        out.extend_from_slice(&self.id.to_be_bytes());
        out.extend_from_slice(&self.flags_frag.to_be_bytes());
        out.push(self.ttl);
        out.push(self.proto);
        out.extend_from_slice(&[0,0]); // checksum placeholder
        out.extend_from_slice(&self.src);
        out.extend_from_slice(&self.dst);

        // compute checksum over header
        let c = csum16(&out[..20]);
        out[10] = (c >> 8) as u8;
        out[11] = (c & 0xff) as u8;

        out.extend_from_slice(payload);
    }

    pub fn parse(pkt: &[u8]) -> Option<(Ipv4Hdr, &[u8])> {
        if pkt.len() < 20 { return None; }
        let ihl = pkt[0] & 0x0f;
        if ihl != 5 { return None; } // no options for learning stack
        let tot = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
        if pkt.len() < tot { return None; }
        let hdr = Ipv4Hdr {
            tos: pkt[1],
            id: u16::from_be_bytes([pkt[4],pkt[5]]),
            flags_frag: u16::from_be_bytes([pkt[6],pkt[7]]),
            ttl: pkt[8],
            proto: pkt[9],
            src: [pkt[12],pkt[13],pkt[14],pkt[15]],
            dst: [pkt[16],pkt[17],pkt[18],pkt[19]],
        };
        Some((hdr, &pkt[20..tot]))
    }
}
