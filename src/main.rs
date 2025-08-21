mod netdev;
mod util;
mod l2;
mod arp;
mod ipv4;
mod icmp;
mod tcp;
mod api;

use crate::netdev::tap::Tap;
use crate::api::echo::run_echo_server;

fn main() {
    // Defaults you can tweak via env if you wish
    let ifname = std::env::var("TAP_IF").unwrap_or_else(|_| "tap0".to_string());
    let our_mac = std::env::var("OUR_MAC").unwrap_or_else(|_| "02:00:00:00:00:01".to_string());
    let our_ip  = std::env::var("OUR_IP").unwrap_or_else(|_| "10.0.0.1".to_string());
    let peer_ip = std::env::var("PEER_IP").unwrap_or_else(|_| "10.0.0.2".to_string());

    println!("[stack] opening TAP {ifname} …");
    let tap = Tap::open(&ifname).expect("open tap");

    println!("[stack] starting echo server on 0.0.0.0:8080");
    run_echo_server(tap, &our_mac, &our_ip, &peer_ip, 8080).expect("echo server");
}
