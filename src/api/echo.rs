use crate::netdev::tap::Tap;
use crate::l2::ethernet::{self, Mac, ETH_P_ARP, ETH_P_IPV4};
use crate::arp::{self, Ipv4, ArpCache};
use crate::ipv4::{self, Ipv4Hdr, IP_PROTO_ICMP, IP_PROTO_TCP};
use crate::icmp;
use crate::tcp::{self, TcpStack, TcpSeg, serialize_tcp, WireSeg, FourTuple};
use crate::util::time::now_millis;

use std::io::Result;
use std::time::{Instant, Duration};

pub fn run_echo_server(
    mut tap: Tap,
    our_mac_s: &str, our_ip_s: &str, peer_ip_s: &str,
    listen_port: u16
) -> Result<()> {
    let our_mac = Mac::parse(our_mac_s);
    let our_ip  = arp::Ipv4::parse(our_ip_s);
    let peer_ip = arp::Ipv4::parse(peer_ip_s);

    let mut arp_cache = ArpCache::new(our_ip, our_mac);
    let mut tcp = TcpStack::new();
    tcp.listen(listen_port);

    let mut rx = [0u8; 4096];
    let mut last_arp = Instant::now() - Duration::from_secs(10);

    loop {
        // Proactive ARP for peer if we don't know MAC
        if arp_cache.lookup(peer_ip).is_none() && last_arp.elapsed() > Duration::from_millis(500) {
            let arp_req = arp::build_request(our_mac, our_ip, peer_ip);
            let mut frame = Vec::with_capacity(14 + arp_req.len());
            ethernet::build(ethernet::Mac::broadcast(), our_mac, ETH_P_ARP, &arp_req, &mut frame);
            let _ = tap.send(&frame)?;
            last_arp = Instant::now();
        }

        // poll RX (non-blocking-friendly)
        let n = tap.recv(&mut rx)?;
        if n < 14 { 
            // even if no useful packet, drive timers
            let mut timed = tcp.on_timer(now_millis());
            for (meta, seg) in timed.drain(..) { send_tcp(&mut tap, our_mac, &mut arp_cache, meta, seg); }
            continue;
        }

        let now = now_millis();

        if let Some((et, dst, src, payload)) = ethernet::parse(&rx[..n]) {
            // Only ours/broadcast
            if dst != &our_mac.0 && dst != &ethernet::Mac::broadcast().0 { 
                let mut timed = tcp.on_timer(now);
                for (meta, seg) in timed.drain(..) { send_tcp(&mut tap, our_mac, &mut arp_cache, meta, seg); }
                continue; 
            }

            match et {
                ETH_P_ARP => {
                    if let Some((op, smac, sip, _tmac, tip)) = arp::parse(payload) {
                        arp_cache.insert(sip, smac);
                        if op == 1 && tip.0 == our_ip.0 {
                            let reply = arp::build_reply(our_mac, our_ip, smac, sip);
                            let mut frame = Vec::new();
                            ethernet::build(smac, our_mac, ETH_P_ARP, &reply, &mut frame);
                            let _ = tap.send(&frame)?;
                        }
                    }
                }
                ETH_P_IPV4 => {
                    if let Some((ip, l4)) = ipv4::Ipv4Hdr::parse(payload) {
                        if ip.dst != our_ip.0 { 
                            let mut timed = tcp.on_timer(now);
                            for (meta, seg) in timed.drain(..) { send_tcp(&mut tap, our_mac, &mut arp_cache, meta, seg); }
                            continue; 
                        }

                        match ip.proto {
                            IP_PROTO_ICMP => {
                                if let Some((id, seq, data)) = icmp::parse_echo(l4) {
                                    let reply = icmp::build_echo_reply(id, seq, data);
                                    let mut ipb = Vec::new();
                                    Ipv4Hdr{ tos:0,id:0,flags_frag:0,ttl:64,proto:IP_PROTO_ICMP, src:our_ip.0,dst:ip.src }
                                      .serialize(&reply, &mut ipb);

                                    if let Some(dstmac) = arp_cache.lookup(arp::Ipv4(ip.src)) {
                                        let mut frame = Vec::new();
                                        ethernet::build(dstmac, our_mac, ETH_P_IPV4, &ipb, &mut frame);
                                        let _ = tap.send(&frame)?;
                                    }
                                }
                            }
                            IP_PROTO_TCP => {
                                if let Some(seg) = tcp::parse_tcp(l4) {
                                    // demux key (peer -> us)
                                    let key = FourTuple{
                                        src_ip: ip.src, dst_ip: ip.dst,
                                        src_port: seg.src_port, dst_port: seg.dst_port
                                    };
                                    let mut responses = tcp.on_segment(now, key, &seg);
                                    for (meta, r) in responses.drain(..) {
                                        send_tcp(&mut tap, our_mac, &mut arp_cache, meta, r);
                                    }

                                    // If app data arrived in any ESTABLISHED conn, echo it back:
                                    if let Some(conn) = tcp.conns.get_mut(&key) {
                                        let mut drain = Vec::new();
                                        while let Some(b) = conn.tcb.app_read.pop_front() {
                                            drain.push(b);
                                        }
                                        if !drain.is_empty() {
                                            let mut resp = tcp.send_app(&key, &drain, now);
                                            for (meta, r) in resp.drain(..) {
                                                send_tcp(&mut tap, our_mac, &mut arp_cache, meta, r);
                                            }
                                        }
                                    }
                                }
                            }
                            _ => { /* ignore */ }
                        }
                    }
                }
                _ => {}
            }
        }

        // Drive timers even when we had RX
        let mut timed = tcp.on_timer(now);
        for (meta, seg) in timed.drain(..) { send_tcp(&mut tap, our_mac, &mut arp_cache, meta, seg); }
    }
}

fn send_tcp(
    tap: &mut Tap, our_mac: crate::l2::ethernet::Mac, arp_cache: &mut ArpCache,
    meta: crate::tcp::ConnMeta, seg: WireSeg<'_>
) {
    // serialize TCP
    let tcpb = serialize_tcp(&seg, meta.ip_src, meta.ip_dst);
    // IP
    let mut ipb = Vec::new();
    crate::ipv4::Ipv4Hdr{
        tos:0,id:0,flags_frag:0,ttl:64,proto:crate::ipv4::IP_PROTO_TCP,
        src:meta.ip_src,dst:meta.ip_dst
    }.serialize(&tcpb, &mut ipb);

    // L2 dest MAC via ARP cache (best-effort)
    if let Some(dstmac) = arp_cache.lookup(arp::Ipv4(meta.ip_dst)) {
        let mut frame = Vec::new();
        crate::l2::ethernet::build(dstmac, our_mac, crate::l2::ethernet::ETH_P_IPV4, &ipb, &mut frame);
        let _ = tap.send(&frame);
    }
}
