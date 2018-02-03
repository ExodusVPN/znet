#[macro_use]
extern crate cfg_if;
#[cfg(unix)]
extern crate nix;
extern crate ipnetwork;
extern crate smoltcp;


use nix::libc;

pub use ipnetwork::{
    IpNetwork, Ipv4Network, Ipv6Network, IpNetworkError,
    ip_mask_to_prefix, ipv4_mask_to_prefix, ipv6_mask_to_prefix,
};
pub use smoltcp::wire::{
    EthernetAddress,
    IpAddress, Ipv4Address, Ipv6Address,
    IpCidr, Ipv4Cidr, Ipv6Cidr, IpEndpoint,
};


mod sys;
#[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "linux"))]
pub mod interface;
// #[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "linux"))]
// pub mod raw_socket;
pub mod stack {
    pub use super::smoltcp::socket::TcpSocket;
    pub use super::smoltcp::socket::UdpSocket;
}

