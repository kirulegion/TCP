pub fn hexline(b: &[u8]) -> String {
    let mut s = String::new();
    for (i, x) in b.iter().enumerate() {
        if i > 0 { s.push(' '); }
        s.push_str(&format!("{:02x}", x));
    }
    s
}
