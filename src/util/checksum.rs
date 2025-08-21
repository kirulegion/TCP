// 16-bit 1's complement sum (RFC 1071)
pub fn csum16(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = data.chunks_exact(2);
    for c in &mut chunks {
        let w = u16::from_be_bytes([c[0], c[1]]) as u32;
        sum = sum.wrapping_add(w);
    }
    if let Some(&rem) = chunks.remainder().first() {
        let w = u16::from_be_bytes([rem, 0]) as u32;
        sum = sum.wrapping_add(w);
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

// Pseudo-header TCP checksum over IPv4
pub fn tcp_ipv4_csum(src: [u8;4], dst: [u8;4], proto: u8, tcp: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(12 + tcp.len());
    pseudo.extend_from_slice(&src);
    pseudo.extend_from_slice(&dst);
    pseudo.push(0);
    pseudo.push(proto);
    pseudo.extend_from_slice(&(tcp.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(tcp);
    csum16(&pseudo)
}
