use std::sync::OnceLock;
use std::time::{Duration, Instant};

pub struct Timer {
    start: Instant,
}
impl Timer {
    pub fn start() -> Self { Self { start: Instant::now() } }
    pub fn elapsed(&self) -> Duration { self.start.elapsed() }
}

static START: OnceLock<Instant> = OnceLock::new();
pub fn now_millis() -> u128 {
    *START.get_or_init(Instant::now);
    START.get().unwrap().elapsed().as_millis()
}

/// RFC 6298-ish RTO (simplified)
#[derive(Clone, Debug)]
pub struct RtoCalc {
    inited: bool,
    srtt: f64,
    rttvar: f64,
    pub rto_ms: u64,
}
impl RtoCalc {
    pub fn new() -> Self {
        Self { inited: false, srtt: 0.0, rttvar: 0.0, rto_ms: 1000 }
    }
    pub fn sample(&mut self, rtt_ms: u64) {
        let rtt = rtt_ms as f64;
        if !self.inited {
            self.inited = true;
            self.srtt = rtt;
            self.rttvar = rtt / 2.0;
        } else {
            let a = 1.0/8.0;
            let b = 1.0/4.0;
            let err = (self.srtt - rtt).abs();
            self.rttvar = (1.0 - b) * self.rttvar + b * err;
            self.srtt   = (1.0 - a) * self.srtt   + a * rtt;
        }
        let mut rto = self.srtt + 4.0 * self.rttvar;
        if rto < 200.0 { rto = 200.0; }
        if rto > 60000.0 { rto = 60000.0; }
        self.rto_ms = rto as u64;
    }
    pub fn backoff(&mut self) {
        self.rto_ms = (self.rto_ms * 2).clamp(200, 120_000);
    }
}
