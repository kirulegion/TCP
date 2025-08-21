use std::fs::{OpenOptions, File};
use std::io::{Read, Write, Result};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::io::FromRawFd;

#[repr(C)]
struct IfReq {
    ifr_name: [u8; 16],
    ifr_flags: u16,
    _pad: [u8; 22], // enough to match size (varies by arch; keep simple)
}

const TUNSETIFF: u64 = 0x400454ca;
const IFF_TAP: u16 = 0x0002;
const IFF_NO_PI: u16 = 0x1000;

unsafe extern "C" {
    fn ioctl(fd: RawFd, request: u64, argp: *mut IfReq) -> i32;
}

pub struct Tap {
    f: File,
}

impl Tap {
    pub fn open(name: &str) -> Result<Tap> {
        let f = OpenOptions::new().read(true).write(true).open("/dev/net/tun")?;
        let fd = f.as_raw_fd();

        let mut ifr = IfReq {
            ifr_name: [0; 16],
            ifr_flags: IFF_TAP | IFF_NO_PI,
            _pad: [0; 22],
        };
        for (i, b) in name.as_bytes().iter().enumerate().take(16) {
            ifr.ifr_name[i] = *b;
        }

        let rc = unsafe { ioctl(fd, TUNSETIFF, &mut ifr as *mut _) };
        if rc < 0 {
            panic!("ioctl TUNSETIFF failed (are you root? does {name} exist?)");
        }

        // Safety: fd owned by File f; we keep f
        Ok(Tap { f })
    }

    pub fn recv(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.f.read(buf)
    }

    pub fn send(&mut self, buf: &[u8]) -> Result<usize> {
        self.f.write(buf)
    }
}
