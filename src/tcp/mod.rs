use std::cmp::{max, min};
use std::collections::{BTreeMap, HashMap, VecDeque};
use crate::util::checksum::tcp_ipv4_csum;

// ---------- constants ----------
pub const TCP_FLAG_FIN: u16 = 0x01;
pub const TCP_FLAG_SYN: u16 = 0x02;
pub const TCP_FLAG_RST: u16 = 0x04;
pub const TCP_FLAG_PSH: u16 = 0x08;
pub const TCP_FLAG_ACK: u16 = 0x10;

const MAX_SEG: usize = 1460;
const INIT_CWND: usize = 2 * MAX_SEG;
const INIT_SSTHRESH: usize = 64 * 1024;
const DUPACK_THRESHOLD: u32 = 3;
const DELAYED_ACK_MS: u64 = 80;
const TIME_WAIT_MS: u64 = 2_000;

// ---------- state ----------
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Closed,
    Listen,
    SynRcvd,
    SynSent,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    LastAck,
    Closing,
    TimeWait,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FourTuple {
    pub src_ip: [u8; 4],
    pub dst_ip: [u8; 4],
    pub src_port: u16,
    pub dst_port: u16,
}

// inbound parsed segment
pub struct TcpSeg<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u16,
    pub wnd: u16,
    pub payload: &'a [u8],
}

pub fn parse_tcp(pkt: &[u8]) -> Option<TcpSeg> {
    if pkt.len() < 20 {
        return None;
    }
    let src = u16::from_be_bytes([pkt[0], pkt[1]]);
    let dst = u16::from_be_bytes([pkt[2], pkt[3]]);
    let seq = u32::from_be_bytes([pkt[4], pkt[5], pkt[6], pkt[7]]);
    let ack = u32::from_be_bytes([pkt[8], pkt[9], pkt[10], pkt[11]]);
    let data_off = (pkt[12] >> 4) as usize;
    let flags = pkt[13] as u16;
    let wnd = u16::from_be_bytes([pkt[14], pkt[15]]);
    let hlen = data_off * 4;
    if pkt.len() < hlen {
        return None;
    }
    let payload = &pkt[hlen..];
    Some(TcpSeg { src_port: src, dst_port: dst, seq, ack, flags, wnd, payload })
}

fn put_be16(v: u16, out: &mut Vec<u8>) {
    out.extend_from_slice(&v.to_be_bytes());
}
fn put_be32(v: u32, out: &mut Vec<u8>) {
    out.extend_from_slice(&v.to_be_bytes());
}

pub struct WireSeg<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u16,
    pub wnd: u16,
    pub payload: &'a [u8],
}

pub fn serialize_tcp(h: &WireSeg, ip_src: [u8; 4], ip_dst: [u8; 4]) -> Vec<u8> {
    let data_off = 5u8 << 4; // no options
    let mut p = Vec::with_capacity(20 + h.payload.len());
    put_be16(h.src_port, &mut p);
    put_be16(h.dst_port, &mut p);
    put_be32(h.seq, &mut p);
    put_be32(h.ack, &mut p);
    p.push(data_off);
    p.push((h.flags & 0xff) as u8);
    put_be16(h.wnd, &mut p);
    p.extend_from_slice(&[0, 0]); // checksum placeholder
    put_be16(0, &mut p); // urg ptr
    p.extend_from_slice(h.payload);

    let c = tcp_ipv4_csum(ip_src, ip_dst, 6, &p);
    p[16] = (c >> 8) as u8;
    p[17] = (c & 0xff) as u8;
    p
}

// ----- connection control block -----
#[derive(Clone, Debug)]
pub struct Tcb {
    pub state: State,
    pub iss: u32,
    pub irs: u32,
    pub snd_una: u32,
    pub snd_nxt: u32,
    pub snd_wnd: u32,
    pub rcv_nxt: u32,
    pub rcv_wnd: u32,
    pub local_port: u16,
    pub remote_port: u16,
    pub local_isn: u32,

    // cc / timers / acks
    pub cwnd: usize,
    pub ssthresh: usize,
    pub dupacks: u32,
    pub ack_due_ms: u128,
    pub timewait_until_ms: u128,

    // RTT/RTO
    pub rto: crate::util::time::RtoCalc,

    // send tracking
    pub mss: usize,
    pub flight: usize,                      // bytes outstanding
    pub sendq: VecDeque<u8>,                // app data queued
    pub unacked: BTreeMap<u32, (usize, u128)>, // seq -> (len, sent_ms)

    // receive reassembly
    pub ooo: BTreeMap<u32, Vec<u8>>, // seq -> payload
    pub app_read: VecDeque<u8>,      // in-order for app
}

impl Tcb {
    pub fn new_listen(port: u16) -> Self {
        Self {
            state: State::Listen,
            iss: 0,
            irs: 0,
            snd_una: 0,
            snd_nxt: 0,
            snd_wnd: 65535,
            rcv_nxt: 0,
            rcv_wnd: 65535,
            local_port: port,
            remote_port: 0,
            local_isn: 0x1234_5678,
            cwnd: INIT_CWND,
            ssthresh: INIT_SSTHRESH,
            dupacks: 0,
            ack_due_ms: 0,
            timewait_until_ms: 0,
            rto: crate::util::time::RtoCalc::new(),
            mss: MAX_SEG,
            flight: 0,
            sendq: VecDeque::new(),
            unacked: BTreeMap::new(),
            ooo: BTreeMap::new(),
            app_read: VecDeque::new(),
        }
    }
}

// One connection plus its addressing
#[derive(Clone)]
pub struct ConnMeta {
    pub key: FourTuple,
    pub ip_src: [u8; 4],
    pub ip_dst: [u8; 4],
}
pub struct TcpConn {
    pub tcb: Tcb,
    pub meta: ConnMeta,
}

pub struct TcpStack {
    pub listeners: HashMap<u16, ()>,
    pub conns: HashMap<FourTuple, TcpConn>,
}

impl TcpStack {
    pub fn new() -> Self {
        Self { listeners: HashMap::new(), conns: HashMap::new() }
    }
    pub fn listen(&mut self, port: u16) {
        self.listeners.insert(port, ());
    }

    pub fn on_segment<'a>(
        &mut self,
        now_ms: u128,
        key: FourTuple,
        l4: &TcpSeg<'a>,
    ) -> Vec<(ConnMeta, WireSeg<'static>)> {
        if let Some(c) = self.conns.get_mut(&key) {
            return conn_on_segment(c, now_ms, l4);
        }
        if (l4.flags & TCP_FLAG_SYN) != 0 && self.listeners.contains_key(&l4.dst_port) {
            let mut tcb = Tcb::new_listen(l4.dst_port);
            tcb.state = State::SynRcvd;
            tcb.remote_port = l4.src_port;
            tcb.irs = l4.seq;
            tcb.rcv_nxt = l4.seq.wrapping_add(1);
            tcb.iss = tcb.local_isn;
            tcb.snd_una = tcb.iss;
            tcb.snd_nxt = tcb.iss.wrapping_add(1);

            let meta = ConnMeta { key, ip_src: key.dst_ip, ip_dst: key.src_ip };
            let mut conn = TcpConn { tcb, meta: meta.clone() };
            let synack = WireSeg {
                src_port: conn.tcb.local_port,
                dst_port: conn.tcb.remote_port,
                seq: conn.tcb.iss,
                ack: conn.tcb.rcv_nxt,
                flags: TCP_FLAG_SYN | TCP_FLAG_ACK,
                wnd: conn.tcb.rcv_wnd as u16,
                payload: &[],
            };
            self.conns.insert(key, conn);
            return vec![(meta, synack)];
        }
        vec![]
    }

    pub fn on_timer(&mut self, now_ms: u128) -> Vec<(ConnMeta, WireSeg<'static>)> {
        let mut out = Vec::new();
        let keys: Vec<_> = self.conns.keys().cloned().collect();
        for k in keys {
            if let Some(c) = self.conns.get_mut(&k) {
                // TIME-WAIT cleanup
                if c.tcb.state == State::TimeWait && now_ms >= c.tcb.timewait_until_ms {
                    self.conns.remove(&k);
                    continue;
                }
                // delayed ACK
                if c.tcb.ack_due_ms != 0
                    && now_ms >= c.tcb.ack_due_ms
                    && c.tcb.state == State::Established
                {
                    let seg = WireSeg {
                        src_port: c.tcb.local_port,
                        dst_port: c.tcb.remote_port,
                        seq: c.tcb.snd_nxt,
                        ack: c.tcb.rcv_nxt,
                        flags: TCP_FLAG_ACK,
                        wnd: c.tcb.rcv_wnd as u16,
                        payload: &[],
                    };
                    c.tcb.ack_due_ms = 0;
                    out.push((c.meta.clone(), seg));
                }
                // RTO on oldest unacked
                if let Some((&seq, &(len, sent_at))) = c.tcb.unacked.iter().next() {
                    let rto_u128 = c.tcb.rto.rto_ms as u128;
                    if now_ms.saturating_sub(sent_at) >= rto_u128 {
                        // placeholder payload of correct length
                        let payload_box = vec![0u8; len].into_boxed_slice();
                        let payload: &'static [u8] = Box::leak(payload_box);
                        let seg = WireSeg {
                            src_port: c.tcb.local_port,
                            dst_port: c.tcb.remote_port,
                            seq,
                            ack: c.tcb.rcv_nxt,
                            flags: TCP_FLAG_ACK,
                            wnd: c.tcb.rcv_wnd as u16,
                            payload,
                        };
                        c.tcb.rto.backoff();
                        c.tcb.ssthresh = max(c.tcb.cwnd / 2, 2 * MAX_SEG);
                        c.tcb.cwnd = MAX_SEG;
                        out.push((c.meta.clone(), seg));
                    }
                }
                // zero-window probe
                if c.tcb.snd_wnd == 0 && !c.tcb.sendq.is_empty() && c.tcb.state == State::Established
                {
                    let seg = WireSeg {
                        src_port: c.tcb.local_port,
                        dst_port: c.tcb.remote_port,
                        seq: c.tcb.snd_nxt.wrapping_sub(1),
                        ack: c.tcb.rcv_nxt,
                        flags: TCP_FLAG_ACK,
                        wnd: c.tcb.rcv_wnd as u16,
                        payload: &[],
                    };
                    out.push((c.meta.clone(), seg));
                }
                // try send new data
                let mut more = conn_try_send(c, now_ms);
                out.append(&mut more);
            }
        }
        out
    }

    pub fn send_app(
        &mut self,
        key: &FourTuple,
        data: &[u8],
        now_ms: u128,
    ) -> Vec<(ConnMeta, WireSeg<'static>)> {
        if let Some(c) = self.conns.get_mut(key) {
            for b in data {
                c.tcb.sendq.push_back(*b);
            }
            return conn_try_send(c, now_ms);
        }
        vec![]
    }
}

// ---- helpers ----

fn conn_on_segment<'a>(
    c: &mut TcpConn,
    now_ms: u128,
    seg: &TcpSeg<'a>,
) -> Vec<(ConnMeta, WireSeg<'static>)> {
    let t = &mut c.tcb;
    let mut out = Vec::new();

    // peer window
    t.snd_wnd = seg.wnd as u32;

    // ACK processing (advance snd_una, RTT sample)
    if (seg.flags & TCP_FLAG_ACK) != 0 {
        if seg.ack.wrapping_sub(t.snd_una) as i32 > 0 {
            // RTT sample using head unacked
            if let Some((&first_seq, &(len, sent_at))) = t.unacked.iter().next() {
                if seg.ack.wrapping_sub(first_seq) as i32 >= len as i32 {
                    let rtt = now_ms.saturating_sub(sent_at) as u64;
                    if rtt > 0 {
                        t.rto.sample(rtt);
                    }
                }
            }
            // remove acked
            let keys: Vec<u32> = t.unacked.keys().cloned().collect();
            let mut newly = 0usize;
            for k in keys {
                let (len, _) = *t.unacked.get(&k).unwrap();
                if seg.ack.wrapping_sub(k) as i32 >= len as i32 {
                    t.unacked.remove(&k);
                    newly += len;
                }
            }
            t.snd_una = seg.ack;
            t.flight = t.flight.saturating_sub(newly);

            // CC growth
            if newly > 0 {
                if t.cwnd < t.ssthresh {
                    t.cwnd += newly;
                } else {
                    t.cwnd += (MAX_SEG * newly) / t.cwnd.max(1);
                }
            }
            t.dupacks = 0;
        } else if seg.ack == t.snd_una && !t.unacked.is_empty() && seg.payload.is_empty() {
            // DUP-ACK
            t.dupacks += 1;
            if t.dupacks >= DUPACK_THRESHOLD {
                if let Some((&seq, &(len, _))) = t.unacked.iter().next() {
                    let payload_box = vec![0u8; len].into_boxed_slice();
                    let payload: &'static [u8] = Box::leak(payload_box);
                    let rs = WireSeg {
                        src_port: t.local_port,
                        dst_port: t.remote_port,
                        seq,
                        ack: t.rcv_nxt,
                        flags: TCP_FLAG_ACK,
                        wnd: t.rcv_wnd as u16,
                        payload,
                    };
                    t.ssthresh = max(t.cwnd / 2, 2 * MAX_SEG);
                    t.cwnd = t.ssthresh + 3 * MAX_SEG;
                    out.push((c.meta.clone(), rs));
                }
            }
        }
    }

    match t.state {
        State::SynRcvd => {
            if (seg.flags & TCP_FLAG_ACK) != 0 && seg.ack == t.snd_nxt {
                t.snd_una = seg.ack;
                t.state = State::Established;
            }
        }
        State::Established => {
            // inbound data
            if !seg.payload.is_empty() {
                if seg.seq == t.rcv_nxt {
                    t.rcv_nxt = t.rcv_nxt.wrapping_add(seg.payload.len() as u32);
                    t.app_read.extend(seg.payload);

                    // pull ooo
                    loop {
                        if let Some((&seq, data)) = t.ooo.iter().next() {
                            if seq == t.rcv_nxt {
                                t.rcv_nxt = t.rcv_nxt.wrapping_add(data.len() as u32);
                                for b in data {
                                    t.app_read.push_back(*b);
                                }
                                t.ooo.remove(&seq);
                                continue;
                            }
                        }
                        break;
                    }
                    t.ack_due_ms = now_ms + DELAYED_ACK_MS as u128;
                } else if seq_before(seg.seq, t.rcv_nxt) {
                    // old -> immediate ACK
                    out.push((
                        c.meta.clone(),
                        WireSeg {
                            src_port: t.local_port,
                            dst_port: t.remote_port,
                            seq: t.snd_nxt,
                            ack: t.rcv_nxt,
                            flags: TCP_FLAG_ACK,
                            wnd: t.rcv_wnd as u16,
                            payload: &[],
                        },
                    ));
                } else {
                    // future -> store & dup-ack
                    t.ooo.insert(seg.seq, seg.payload.to_vec());
                    out.push((
                        c.meta.clone(),
                        WireSeg {
                            src_port: t.local_port,
                            dst_port: t.remote_port,
                            seq: t.snd_nxt,
                            ack: t.rcv_nxt,
                            flags: TCP_FLAG_ACK,
                            wnd: t.rcv_wnd as u16,
                            payload: &[],
                        },
                    ));
                }
            }

            // FIN from peer
            if (seg.flags & TCP_FLAG_FIN) != 0 {
                t.rcv_nxt = t.rcv_nxt.wrapping_add(1);
                out.push((
                    c.meta.clone(),
                    WireSeg {
                        src_port: t.local_port,
                        dst_port: t.remote_port,
                        seq: t.snd_nxt,
                        ack: t.rcv_nxt,
                        flags: TCP_FLAG_ACK,
                        wnd: t.rcv_wnd as u16,
                        payload: &[],
                    },
                ));
                let fin = WireSeg {
                    src_port: t.local_port,
                    dst_port: t.remote_port,
                    seq: t.snd_nxt,
                    ack: t.rcv_nxt,
                    flags: TCP_FLAG_FIN | TCP_FLAG_ACK,
                    wnd: t.rcv_wnd as u16,
                    payload: &[],
                };
                t.snd_nxt = t.snd_nxt.wrapping_add(1);
                t.state = State::LastAck;
                out.push((c.meta.clone(), fin));
            }
        }
        State::LastAck => {
            if (seg.flags & TCP_FLAG_ACK) != 0 && seg.ack == t.snd_nxt {
                t.state = State::TimeWait;
                t.timewait_until_ms = now_ms + TIME_WAIT_MS as u128;
            }
        }
        _ => {}
    }

    let mut more = conn_try_send(c, now_ms);
    out.append(&mut more);
    out
}

fn conn_try_send(c: &mut TcpConn, now_ms: u128) -> Vec<(ConnMeta, WireSeg<'static>)> {
    let t = &mut c.tcb;
    let mut out = Vec::new();

    let cwnd_room = t.cwnd.saturating_sub(t.flight);
    let rwnd_room = (t.snd_wnd as usize).saturating_sub(t.flight);
    let budget = min(cwnd_room, rwnd_room);

    if budget == 0 || t.sendq.is_empty() {
        return out;
    }
    let to_send = min(budget, min(t.sendq.len(), t.mss));
    let mut v = vec![0u8; to_send];
    for i in 0..to_send {
        if let Some(b) = t.sendq.pop_front() {
            v[i] = b;
        }
    }
    let payload_box = v.into_boxed_slice();
    let payload: &'static [u8] = Box::leak(payload_box);

    let seg = WireSeg {
        src_port: t.local_port,
        dst_port: t.remote_port,
        seq: t.snd_nxt,
        ack: t.rcv_nxt,
        flags: TCP_FLAG_ACK | TCP_FLAG_PSH,
        wnd: t.rcv_wnd as u16,
        payload,
    };

    t.unacked.insert(t.snd_nxt, (to_send, now_ms));
    t.snd_nxt = t.snd_nxt.wrapping_add(to_send as u32);
    t.flight += to_send;

    out.push((c.meta.clone(), seg));
    out
}

#[inline]
fn seq_before(a: u32, b: u32) -> bool {
    (a as i32).wrapping_sub(b as i32) < 0
}
