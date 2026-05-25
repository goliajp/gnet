//! Linux TUN device via `/dev/net/tun` (`IFF_TUN | IFF_NO_PI`: raw IP
//! packets, no per-packet header).

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

const O_RDWR: i32 = 2;
const IFF_TUN: u16 = 0x0001;
const IFF_NO_PI: u16 = 0x1000;
// _IOW('T', 202, int)
const TUNSETIFF: u64 = 0x4004_54ca;
const TUN_PATH: &[u8] = b"/dev/net/tun\0";

#[repr(C)]
#[allow(dead_code)] // `flags` is read by the kernel via FFI; `_pad` is layout
struct IfReq {
    name: [u8; 16],
    flags: u16,
    _pad: [u8; 22],
}

unsafe extern "C" {
    // open/ioctl are variadic in C; declare them so to use the correct ABI.
    fn open(path: *const u8, flags: i32, ...) -> i32;
    fn ioctl(fd: i32, request: u64, ...) -> i32;
    fn read(fd: i32, buf: *mut u8, count: usize) -> isize;
    fn write(fd: i32, buf: *const u8, count: usize) -> isize;
}

/// An open Linux TUN device.
pub struct Tun {
    fd: OwnedFd,
    name: String,
}

impl Tun {
    /// Open the next available TUN device. Requires `CAP_NET_ADMIN` (root).
    pub fn open() -> io::Result<Tun> {
        // SAFETY: opening a device path with O_RDWR; -1 signals error.
        let raw = unsafe { open(TUN_PATH.as_ptr(), O_RDWR) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `raw` is a fresh, valid fd; OwnedFd owns it (closes on drop).
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };

        let mut ifr = IfReq {
            name: [0; 16],
            flags: IFF_TUN | IFF_NO_PI,
            _pad: [0; 22],
        };
        // SAFETY: fd valid; `ifr` is a well-formed ifreq; the kernel fills in
        // the assigned interface name.
        if unsafe { ioctl(fd.as_raw_fd(), TUNSETIFF, &raw mut ifr) } < 0 {
            return Err(io::Error::last_os_error());
        }

        let nlen = ifr
            .name
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(ifr.name.len());
        let name = String::from_utf8_lossy(&ifr.name[..nlen]).into_owned();
        Ok(Tun { fd, name })
    }

    /// The kernel-assigned interface name (e.g. `tun0`).
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Read one IP packet (raw, no header — `IFF_NO_PI`).
    pub fn recv(&self, packet: &mut [u8]) -> io::Result<usize> {
        // SAFETY: fd valid; `packet` is a valid writable region.
        let n = unsafe { read(self.fd.as_raw_fd(), packet.as_mut_ptr(), packet.len()) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(n as usize)
    }

    /// Write one IP packet (raw, no header — `IFF_NO_PI`).
    pub fn send(&self, packet: &[u8]) -> io::Result<usize> {
        // SAFETY: fd valid; `packet` is a valid readable region.
        let n = unsafe { write(self.fd.as_raw_fd(), packet.as_ptr(), packet.len()) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(n as usize)
    }
}
