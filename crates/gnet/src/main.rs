//! `gnet` — a secure UDP channel (and TUN tunnel) over the in-house mesh
//! stack.
//!
//! ```text
//! gnet keygen
//! gnet listen  <bind_addr> <private_hex>
//! gnet connect <peer_addr> <private_hex> <peer_public_hex>
//! gnet tunnel-listen  <bind_addr> <private_hex> <local_ip> <peer_ip>          (macOS)
//! gnet tunnel-connect <peer_addr> <private_hex> <peer_public_hex> <local_ip> <peer_ip>  (macOS)
//! ```

use std::io::{self, BufRead};
use std::net::{SocketAddr, UdpSocket};
use std::process::ExitCode;

use gnet::{channel, keys};
use gnet_hex as hex;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let result = match args.get(1).map(String::as_str) {
        Some("keygen") => cmd_keygen(),
        Some("listen") => cmd_listen(&args),
        Some("connect") => cmd_connect(&args),
        Some("tunnel-listen") => cmd_tunnel_listen(&args),
        Some("tunnel-connect") => cmd_tunnel_connect(&args),
        Some("up") => cmd_up(&args),
        _ => {
            eprintln!("usage:");
            eprintln!("  gnet keygen");
            eprintln!("  gnet listen  <bind_addr> <private_hex>");
            eprintln!("  gnet connect <peer_addr> <private_hex> <peer_public_hex>");
            eprintln!("  gnet tunnel-listen  <bind_addr> <private_hex> <local_ip> <peer_ip>");
            eprintln!(
                "  gnet tunnel-connect <peer_addr> <private_hex> <peer_public_hex> <local_ip> <peer_ip>"
            );
            eprintln!("  gnet up <config_path>            (static multi-peer node)");
            return ExitCode::FAILURE;
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn cmd_keygen() -> io::Result<()> {
    let (sk, pk) = keys::generate_static();
    let (mlkem_ek, _dk) = keys::derive_mlkem(&sk);
    println!("private {}", hex::encode(&sk));
    println!("public  {}", hex::encode(&pk));
    println!("mlkem-public {}", hex::encode(&mlkem_ek));
    Ok(())
}

fn arg<'a>(args: &'a [String], i: usize, name: &str) -> io::Result<&'a str> {
    args.get(i)
        .map(String::as_str)
        .ok_or_else(|| io::Error::other(format!("missing {name}")))
}

fn parse_key(s: &str) -> io::Result<[u8; 32]> {
    hex::decode_32(s).ok_or_else(|| io::Error::other("invalid 32-byte hex key"))
}

fn cmd_listen(args: &[String]) -> io::Result<()> {
    let bind = arg(args, 2, "<bind_addr>")?;
    let private = parse_key(arg(args, 3, "<private_hex>")?)?;

    let socket = UdpSocket::bind(bind)?;
    eprintln!(
        "listening on {bind} as {}",
        hex::encode(&keys::public_key(&private))
    );
    let (mut transport, from) = channel::accept(&socket, private)?;
    eprintln!("handshake complete with {from}");
    loop {
        let msg = channel::recv(&socket, &mut transport)?;
        println!("{}", String::from_utf8_lossy(&msg));
    }
}

fn cmd_connect(args: &[String]) -> io::Result<()> {
    let peer: SocketAddr = arg(args, 2, "<peer_addr>")?
        .parse()
        .map_err(|_| io::Error::other("invalid <peer_addr>"))?;
    let private = parse_key(arg(args, 3, "<private_hex>")?)?;
    let peer_public = parse_key(arg(args, 4, "<peer_public_hex>")?)?;

    let socket = UdpSocket::bind("0.0.0.0:0")?;
    let mut transport = channel::connect(&socket, peer, private, peer_public)?;
    eprintln!("handshake complete with {peer}; type lines to send (Ctrl-D to quit)");
    for line in io::stdin().lock().lines() {
        channel::send(&socket, peer, &mut transport, line?.as_bytes())?;
    }
    Ok(())
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn cmd_tunnel_listen(args: &[String]) -> io::Result<()> {
    let bind = arg(args, 2, "<bind_addr>")?;
    let private = parse_key(arg(args, 3, "<private_hex>")?)?;
    let local_ip = arg(args, 4, "<local_ip>")?;
    let peer_ip = arg(args, 5, "<peer_ip>")?;

    let socket = UdpSocket::bind(bind)?;
    eprintln!(
        "waiting for peer on {bind} as {}",
        hex::encode(&keys::public_key(&private))
    );
    let (transport, from) = channel::accept(&socket, private)?;
    eprintln!("handshake complete with {from}");
    gnet::tunnel::run(socket, from, transport, local_ip, peer_ip)
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn cmd_tunnel_connect(args: &[String]) -> io::Result<()> {
    let peer: SocketAddr = arg(args, 2, "<peer_addr>")?
        .parse()
        .map_err(|_| io::Error::other("invalid <peer_addr>"))?;
    let private = parse_key(arg(args, 3, "<private_hex>")?)?;
    let peer_public = parse_key(arg(args, 4, "<peer_public_hex>")?)?;
    let local_ip = arg(args, 5, "<local_ip>")?;
    let peer_ip = arg(args, 6, "<peer_ip>")?;

    let socket = UdpSocket::bind("0.0.0.0:0")?;
    let transport = channel::connect(&socket, peer, private, peer_public)?;
    eprintln!("handshake complete with {peer}");
    gnet::tunnel::run(socket, peer, transport, local_ip, peer_ip)
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn cmd_up(args: &[String]) -> io::Result<()> {
    let path = arg(args, 2, "<config_path>")?;
    let text = std::fs::read_to_string(path)?;
    let config = gnet_config::parse(&text).map_err(io::Error::other)?;
    gnet::node::run(config)
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn cmd_up(_args: &[String]) -> io::Result<()> {
    Err(io::Error::other("node mode requires macOS or Linux (TUN)"))
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn cmd_tunnel_listen(_args: &[String]) -> io::Result<()> {
    Err(io::Error::other("tunnel mode requires macOS (utun)"))
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn cmd_tunnel_connect(_args: &[String]) -> io::Result<()> {
    Err(io::Error::other("tunnel mode requires macOS (utun)"))
}
