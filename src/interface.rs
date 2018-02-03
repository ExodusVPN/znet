
use nix::ifaddrs::{InterfaceAddress, getifaddrs};
use nix::net::if_::InterfaceFlags;
use nix::sys::socket::SockAddr;

use ::{ip_mask_to_prefix, IpNetwork, EthernetAddress, sys};

use std::{io, fmt};
use std::net::{IpAddr, Ipv4Addr};
use std::ffi::CString;


pub type Flags = InterfaceFlags;

// #[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Interface {
    name : String,
    index: u32,
    flags: Flags,
    mtu  : u32,
    hwaddr: Option<EthernetAddress>,
    dstaddr: Option<Ipv4Addr>,
    addrs: Vec<IpNetwork>,
}

impl Interface {
    pub fn with_index(ifindex: u32) -> Result<Interface, io::Error> {
        let ifname = sys::if_index_to_name(ifindex);
        Interface::with_name(&ifname)
    }

    pub fn with_name(ifname: &str) -> Result<Interface, io::Error> {
        let index: u32 = unsafe { sys::if_nametoindex(CString::new(ifname).unwrap().as_ptr()) };
        let mtu: u32 = match sys::if_name_to_mtu(ifname){
            Ok(n) => n as u32,
            Err(e) => return Err(e),
        };

        let mut iface = Interface {
            name : ifname.clone().to_string(),
            index: index,
            flags: Flags::from_bits(0).unwrap(),
            mtu  : mtu,
            
            hwaddr   : None,
            dstaddr  : None,
            addrs: vec![],
        };
        
        for ifaddr in getifaddrs().unwrap() {
            if ifname != ifaddr.interface_name.as_str() {
                continue;
            }
            iface.flags = ifaddr.flags;
            fill(&ifaddr, &mut iface);
        }

        Ok(iface)
    }

    pub fn is_loopback(&self) -> bool {
        self.flags.contains(Flags::IFF_LOOPBACK)
    }

    pub fn is_tap(&self) -> bool {
        !self.is_loopback() 
        && self.flags.contains(Flags::IFF_BROADCAST)
    }

    pub fn is_tun(&self) -> bool {
        // IFF_NO_PI
        !self.is_tap()
        && self.flags.contains(Flags::IFF_POINTOPOINT)
    }

    pub fn name(&self) -> String {
        self.name.clone()
    }

    pub fn index(&self) -> u32 {
        self.index
    }

    pub fn flags(&self) -> Flags {
        self.flags
    }

    pub fn mtu(&self) -> u32 {
        self.mtu
    }
    
    pub fn hwaddr(&self) -> Option<EthernetAddress> {
        self.hwaddr
    }

    pub fn dstaddr(&self) -> Option<Ipv4Addr> {
        self.dstaddr
    }

    pub fn addrs(&self) -> &Vec<IpNetwork> {
        &self.addrs
    }
}


impl fmt::Display for Interface {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let _ = write!(f, "{}: flags={:X}<{}> mtu {} index: {}",
                self.name,
                self.flags.bits(),
                format!("{:?}", self.flags).replace("IFF_", "").replace(" | ", ","),
                self.mtu,
                self.index);
        if self.hwaddr.is_some(){
            let _ = write!(f, "\n    ether {}", self.hwaddr.unwrap());
        }
        for ip_network in self.addrs.iter() {
            match ip_network {
                &IpNetwork::V4(ipv4_network) => {
                    if self.flags.contains(Flags::IFF_BROADCAST) {
                        let _ = write!(f, "\n    inet {} netmask {}",
                                        ipv4_network,
                                        ipv4_network.mask());
                        let _ = write!(f, " broadcast {}", ipv4_network.broadcast());
                    } else if self.flags.contains(Flags::IFF_POINTOPOINT) {
                        let _ = write!(f, "\n    inet {} netmask {}", ipv4_network, ipv4_network.mask());
                        if self.flags.contains(Flags::IFF_BROADCAST) {
                            let _ = write!(f, " broadcast {}", ipv4_network.broadcast());
                        }
                    } else {
                        let _ = write!(f, "\n    inet {} netmask {}",
                                        ipv4_network.ip(),
                                        ipv4_network.mask());
                    }
                }
                &IpNetwork::V6(ipv6_network) => {
                    let _ = write!(f, "\n    inet6 {}", ipv6_network);
                }
            }
        }

        Ok(())
    }
}

fn fill (ifaddr: &InterfaceAddress, iface: &mut Interface){
    if ifaddr.address.is_some() {
        let sock_addr = ifaddr.address.unwrap();
        match sock_addr {
            SockAddr::Inet(inet_addr) => {
                let std_ip = inet_addr.to_std().ip();
                assert_eq!(ifaddr.netmask.is_some(), true);

                let prefix = match ifaddr.netmask.unwrap() {
                    SockAddr::Inet(inet_addr) => {
                        ip_mask_to_prefix(inet_addr.to_std().ip()).unwrap()
                    },
                    _ => { unreachable!() }
                };

                iface.addrs.push(IpNetwork::new(std_ip, prefix).unwrap());
            },
            SockAddr::Unix(_) => { },
            #[cfg(any(target_os = "android", target_os = "linux"))]
            SockAddr::Netlink(_) => { },
            #[cfg(any(target_os = "ios", target_os = "macos"))]
            SockAddr::SysControl(_) => { },
            #[cfg(any(target_os = "dragonfly",
                      target_os = "freebsd",
                      target_os = "ios",
                      target_os = "macos",
                      target_os = "netbsd",
                      target_os = "openbsd",
                      target_os = "android",
                      target_os = "linux"))]
            SockAddr::Link(link_addr) => {
                iface.hwaddr = Some(EthernetAddress::from_bytes(&link_addr.addr()));
            }
        }
    }

    if ifaddr.destination.is_some() {
        let sock_addr = ifaddr.destination.unwrap();
        match sock_addr {
            SockAddr::Inet(inet_addr) => {
                match inet_addr.to_std().ip() {
                    IpAddr::V4(v4_addr) => {
                        iface.dstaddr = Some(v4_addr);
                    },
                    _ => {}
                }
            },
            _ => {}
        }
    }
}

pub fn interfaces () -> Vec<Interface> {
    let mut ifaces: Vec<Interface> = vec![];
    for ifaddr in getifaddrs().unwrap() {
        let name: String = ifaddr.interface_name.clone();
        
        let mut found = false;

        for iface in &mut ifaces {
            if iface.name == name {
                found = true;
                fill(&ifaddr, iface);
            }
        }

        if !found {
            let if_index = sys::if_name_to_index(&name);
            let if_mtu   = sys::if_name_to_mtu(&name).unwrap();
            let mut iface = Interface {
                name : name.clone(),
                index: if_index as u32,
                flags: ifaddr.flags,
                mtu  : if_mtu as u32,

                hwaddr   : None,
                dstaddr  : None,
                addrs: vec![]
            };
            fill(&ifaddr, &mut iface);
            ifaces.push(iface);
        }
    }
    ifaces
}


