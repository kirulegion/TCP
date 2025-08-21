# 🦀 Rust User-Space TCP/IP Stack

A **from-scratch TCP/IP stack in Rust**, built entirely in **user space**, with **no external crates**.  
Implements Ethernet, ARP, IPv4, ICMP, and TCP (50% RFC-level implementation: handshake, retransmissions, flow + congestion control, close).  

This project is purely for **learning and exploration** of networking stacks.  
It is **not production-ready**, but is a great deep dive into how TCP works under the hood.

---

## ✨ Features

- **L2**: Ethernet II framing, MTU handling  
- **ARP**: Neighbor discovery with cache + expiry  
- **IPv4**: Header build/parse, checksum, TTL, routing  
- **ICMPv4**: Echo request/reply, destination unreachable, time exceeded  
- **TCP**:  
  - 3-way handshake (SYN / SYN-ACK / ACK)  
  - State machine (RFC 793 + 1122): LISTEN → ESTABLISHED → CLOSE  
  - Sequence & ACK tracking  
  - Retransmission with RTT/RTO (RFC 6298 simplified)  
  - Flow control (rwnd)  
  - Congestion control: slow start + AIMD, fast retransmit  
  - Connection close with FIN/ACK + TIME-WAIT  
- **API**: Minimal `TcpListener` / `TcpStream` style façade  
- **Examples**: Echo server + client  
- **Test Harness**: Namespace setup + packet capture scripts  

---

## 📂 Project Layout

```text
src/
├── main.rs            # entrypoint
├── netdev/            # raw I/O (TAP device)
│   └── tap.rs
├── util/              # helpers: hexdump, checksums, timers
│   ├── hexdump.rs
│   ├── checksum.rs
│   └── time.rs
├── l2/ethernet.rs     # Ethernet II parser/serializer
├── arp/mod.rs         # ARP cache + protocol
├── ipv4/mod.rs        # IPv4 header, checksum, routing
├── icmp/mod.rs        # ICMPv4 echo + errors
├── tcp/mod.rs         # TCP state machine + transport
└── api/echo.rs        # minimal socket API façade

examples/
├── echo_server.rs     # user-space echo server
└── echo_client.rs     # user-space echo client

scripts/
├── netns_setup.sh     # setup veth + namespaces
├── capture.sh         # run tcpdump
└── run_echo.sh        # test server/client across namespaces

tests/
└── smoke.sh           # basic handshake + echo tests
```


---
  
## 🛠️ Building

```bash
# Clone
git clone https://github.com/you/rust-tcp-stack.git
cd rust-tcp-stack

# Build
cargo build

# Run checks
cargo check
cargo test
```

---

## 🌐 Test Environment

We run inside Linux network namespaces using a TAP device.  

### Setup namespaces
```bash
scripts/netns_setup.sh

nsA (our TCP stack) <—> veth pair <—> nsB (Linux with netcat)

# In nsA (our stack)
cargo run --example echo_server

# In nsB (Linux client)
ip netns exec nsB nc <stack-ip> 8080

scripts/capture.sh
```

---

### Expected Traces
```markdown
## 📊 Expected Traces

### ARP
Who has 10.0.0.2? Tell 10.0.0.1
10.0.0.2 is at aa:bb:cc:dd:ee:ff


### TCP 3-Way Handshake
SYN seq=1000
SYN+ACK seq=5000 ack=1001
ACK seq=1001 ack=5001


### Data Exchange
PSH+ACK "hello"
ACK
PSH+ACK "hello"


### Connection Close
FIN → ACK → FIN → ACK
TIME-WAIT → CLOSED
```

## 📖 Learning Goals

- Understand **packet parsing/serialization** from Ethernet up through TCP.  
- See how **TCP state machine transitions** happen in practice.  
- Explore **timers, retransmissions, and congestion control**.  
- Debug real packet traces with `tcpdump`.  

## ⚠️ Disclaimer

This is **not** a production networking stack.  
It lacks security hardening, performance optimizations, and RFC corner cases.  

It’s intended for:
- Learning  
- Teaching  
- Debugging  
- Having fun with Rust + networking 🦀

## 📌 References

- [RFC 791 — Internet Protocol](https://www.rfc-editor.org/rfc/rfc791)  
- [RFC 792 — ICMP](https://www.rfc-editor.org/rfc/rfc792)  
- [RFC 793 — TCP](https://www.rfc-editor.org/rfc/rfc793)  
- [RFC 1122 — Host Requirements](https://www.rfc-editor.org/rfc/rfc1122)  
- [RFC 6298 — RTO Calculation](https://www.rfc-editor.org/rfc/rfc6298)  
