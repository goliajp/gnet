//! Manual verification (needs root): open a utun, then print every IP packet
//! the kernel routes to it.
//!
//! ```sh
//! sudo cargo run -p gnet-tun --example open_tun
//! # in another terminal, using the printed interface name:
//! sudo ifconfig utunN 10.7.0.1 10.7.0.2 up
//! ping 10.7.0.2          # packets should appear under the example
//! ```

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn main() -> std::io::Result<()> {
    let tun = gnet_tun::Tun::open()?;
    let name = tun.name().to_string();
    println!("opened {name}");
    #[cfg(target_os = "macos")]
    println!("configure: sudo ifconfig {name} 10.7.0.1 10.7.0.2 up");
    #[cfg(target_os = "linux")]
    println!(
        "configure: sudo ip addr add 10.7.0.1 peer 10.7.0.2 dev {name} && sudo ip link set {name} up"
    );
    println!("then ping 10.7.0.2; packets routed into the device print below");
    let mut buf = [0u8; 2048];
    loop {
        let n = tun.recv(&mut buf)?;
        if n > 0 {
            let head = &buf[..n.min(20)];
            println!("packet: {n} bytes  {head:02x?}");
        }
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn main() {
    eprintln!("gnet-tun supports macOS and Linux");
}
