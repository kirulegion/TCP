#[derive(Clone, Copy)]
pub struct Mac(pub [u8;6]);

impl Mac {
    pub fn parse(s: &str) -> Self {
        let b: Vec<u8> = s.split(':')
            .map(|h| u8::from_str_radix(h, 16).unwrap())
            .collect();
        let mut arr = [0u8;6];
        arr.copy_from_slice(&b[..6]);
        Mac(arr)
    }
    pub fn broadcast() -> Self { Mac([0xff;6]) }
}

pub const ETH_P_ARP: u16 = 0x0806;
pub const ETH_P_IPV4: u16 = 0x0800;

#[repr(C, packed)]
pub struct EthHdr {
    pub dst: [u8;6],
    pub src: [u8;6],
    pub ethertype: [u8;2],
}

pub fn build(dst: Mac, src: Mac, ethertype: u16, payload: &[u8], out: &mut Vec<u8>) {
    out.extend_from_slice(&dst.0);
    out.extend_from_slice(&src.0);
    out.extend_from_slice(&ethertype.to_be_bytes());
    out.extend_from_slice(payload);
}

pub fn parse(frame: &[u8]) -> Option<(u16, &[u8;6], &[u8;6], &[u8])> {
    if frame.len() < 14 { return None; }
    let et = u16::from_be_bytes([frame[12], frame[13]]);
    let dst = unsafe { &*(frame[0..6].as_ptr() as *const [u8;6]) };
    let src = unsafe { &*(frame[6..12].as_ptr() as *const [u8;6]) };
    Some((et, dst, src, &frame[14..]))
}
