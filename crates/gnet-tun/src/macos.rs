//! macOS `utun` device via the `PF_SYSTEM` / `SYSPROTO_CONTROL` interface.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

const PF_SYSTEM: i32 = 32;
const SOCK_DGRAM: i32 = 2;
const SYSPROTO_CONTROL: i32 = 2;
const AF_SYSTEM: u8 = 32;
const AF_SYS_CONTROL: u16 = 2;
// _IOWR('N', 3, struct ctl_info) — sizeof(ctl_info) = 100.
const CTLIOCGINFO: u64 = 0xc064_4e03;
const UTUN_OPT_IFNAME: i32 = 2;
const UTUN_CONTROL_NAME: &[u8] = b"com.apple.net.utun_control";
const AF_INET_HEADER: [u8; 4] = [0, 0, 0, 2];
const AF_INET6_HEADER: [u8; 4] = [0, 0, 0, 30];
const READ_BUF: usize = 4 + 2048;

#[repr(C)]
#[allow(dead_code)] // fields are read by the kernel via FFI, not by Rust
struct CtlInfo {
    ctl_id: u32,
    ctl_name: [u8; 96],
}

#[repr(C)]
#[allow(dead_code)] // fields are read by the kernel via FFI, not by Rust
struct SockaddrCtl {
    sc_len: u8,
    sc_family: u8,
    ss_sysaddr: u16,
    sc_id: u32,
    sc_unit: u32,
    sc_reserved: [u32; 5],
}

unsafe extern "C" {
    fn socket(domain: i32, ty: i32, protocol: i32) -> i32;
    // ioctl is variadic in C; the request argument's payload is passed
    // variadically. On Apple aarch64 variadic args go on the stack, so the
    // declaration MUST be variadic or the pointer lands in the wrong place
    // (EFAULT).
    fn ioctl(fd: i32, request: u64, ...) -> i32;
    fn connect(fd: i32, addr: *const SockaddrCtl, len: u32) -> i32;
    fn getsockopt(fd: i32, level: i32, optname: i32, optval: *mut u8, optlen: *mut u32) -> i32;
    fn read(fd: i32, buf: *mut u8, count: usize) -> isize;
    fn write(fd: i32, buf: *const u8, count: usize) -> isize;
}

/// An open macOS `utun` device.
pub struct Tun {
    fd: OwnedFd,
    name: String,
}

impl Tun {
    /// Open the next available `utun` device. Requires root.
    pub fn open() -> io::Result<Tun> {
        // SAFETY: a standard socket(2) call; -1 signals error.
        let raw = unsafe { socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `raw` is a fresh, valid fd; OwnedFd now owns it (closes on drop).
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };

        let mut info = CtlInfo {
            ctl_id: 0,
            ctl_name: [0; 96],
        };
        info.ctl_name[..UTUN_CONTROL_NAME.len()].copy_from_slice(UTUN_CONTROL_NAME);
        // SAFETY: fd is valid; `info` is a valid, writable ctl_info for CTLIOCGINFO.
        if unsafe { ioctl(fd.as_raw_fd(), CTLIOCGINFO, &raw mut info) } < 0 {
            return Err(io::Error::last_os_error());
        }

        // sc_unit = unit + 1; try units until one is free.
        let mut connected = false;
        for unit in 1u32..=256 {
            let addr = SockaddrCtl {
                sc_len: core::mem::size_of::<SockaddrCtl>() as u8,
                sc_family: AF_SYSTEM,
                ss_sysaddr: AF_SYS_CONTROL,
                sc_id: info.ctl_id,
                sc_unit: unit,
                sc_reserved: [0; 5],
            };
            // SAFETY: fd valid; addr is a well-formed sockaddr_ctl of the given length.
            let rc = unsafe {
                connect(
                    fd.as_raw_fd(),
                    &addr,
                    core::mem::size_of::<SockaddrCtl>() as u32,
                )
            };
            if rc == 0 {
                connected = true;
                break;
            }
        }
        if !connected {
            return Err(io::Error::last_os_error());
        }

        let mut name_buf = [0u8; 64];
        let mut len = name_buf.len() as u32;
        // SAFETY: fd valid; name_buf/len are valid out-parameters for getsockopt.
        if unsafe {
            getsockopt(
                fd.as_raw_fd(),
                SYSPROTO_CONTROL,
                UTUN_OPT_IFNAME,
                name_buf.as_mut_ptr(),
                &mut len,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
        let nlen = (len as usize).saturating_sub(1); // drop trailing NUL
        let name = String::from_utf8_lossy(&name_buf[..nlen.min(name_buf.len())]).into_owned();

        Ok(Tun { fd, name })
    }

    /// The kernel-assigned interface name (e.g. `utun4`).
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Read one IP packet, stripping the 4-byte address-family header. Returns
    /// the number of payload bytes written into `packet`.
    pub fn recv(&self, packet: &mut [u8]) -> io::Result<usize> {
        let mut buf = [0u8; READ_BUF];
        // SAFETY: fd valid; buf is a valid writable region of buf.len() bytes.
        let n = unsafe { read(self.fd.as_raw_fd(), buf.as_mut_ptr(), buf.len()) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        let n = n as usize;
        if n < 4 {
            return Ok(0);
        }
        let payload = &buf[4..n];
        let m = payload.len().min(packet.len());
        packet[..m].copy_from_slice(&payload[..m]);
        Ok(m)
    }

    /// Write one IP packet, prepending the 4-byte address-family header that
    /// `utun` requires. The family must match the packet's IP version
    /// (AF_INET = 2 for IPv4, AF_INET6 = 30 for IPv6 on macOS) or the kernel
    /// silently drops the packet.
    pub fn send(&self, packet: &[u8]) -> io::Result<usize> {
        let header = match packet.first().map(|b| b >> 4) {
            Some(6) => &AF_INET6_HEADER,
            _ => &AF_INET_HEADER,
        };
        let mut framed = Vec::with_capacity(4 + packet.len());
        framed.extend_from_slice(header);
        framed.extend_from_slice(packet);
        // SAFETY: fd valid; framed is a valid readable region of framed.len() bytes.
        let n = unsafe { write(self.fd.as_raw_fd(), framed.as_ptr(), framed.len()) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok((n as usize).saturating_sub(4))
    }
}
