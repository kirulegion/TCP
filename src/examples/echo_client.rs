use std::net::{TcpStream};
use std::io::{Write, Read};

fn main() {
    let addr = std::env::var("SERVER_ADDR").unwrap_or("10.0.0.1:8080".to_string());
    let mut s = TcpStream::connect(addr).expect("connect");
    s.write_all(b"hello-from-linux") .unwrap();
    let mut buf = [0u8; 1024];
    let n = s.read(&mut buf).unwrap();
    println!("got {} bytes: {}", n, String::from_utf8_lossy(&buf[..n]));
}
