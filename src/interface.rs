
use nix::ifaddrs::{InterfaceAddress, getifaddrs};
use nix::net::if_::InterfaceFlags;
use nix::sys::socket::SockAddr;

use smoltcp;
use smoltcp::wire::{IpAddress, Ipv6Address, IpCidr, Ipv4Cidr, Ipv6Cidr, EthernetAddress};

use crate::sys;

use std::{io, fmt};
use std::ffi::CString;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub type Flags = InterfaceFlags;


pub fn ipv6_cidr_from_ipv6_mask(address: Ipv6Addr, netmask: Ipv6Addr) -> Result<Ipv6Cidr, smoltcp::Error> {
    const IPV6_SEGMENT_BITS: u8 = 16;

    let mask = netmask.segments();
    let mut mask_iter = mask.into_iter();

    let mut prefix_len = 0u8;
    for &segment in &mut mask_iter {
        if segment == 0xffff {
            prefix_len += IPV6_SEGMENT_BITS;
        } else if segment == 0 {
            break;
        } else {
            let prefix_bits = (!segment).leading_zeros() as u8;
            if segment << prefix_bits != 0 {
                return Err(smoltcp::Error::Illegal);
            }
            prefix_len += prefix_bits;
            break;
        }
    }

    for &segment in mask_iter {
        if segment != 0 {
            return Err(smoltcp::Error::Illegal);
        }
    }

    Ok(Ipv6Cidr::new(Ipv6Address::from(address), prefix_len))
}

pub fn ip_cidr_from_netmask(addr: IpAddress, netmask: IpAddress) -> Result<IpCidr, smoltcp::Error> {
    match addr {
        IpAddress::Ipv4(v4_addr) => {
            match netmask {
                IpAddress::Ipv4(v4_netmask) => Ok(IpCidr::Ipv4(Ipv4Cidr::from_netmask(v4_addr, v4_netmask)?)),
                _ => Err(smoltcp::Error::Illegal)
            }
        },
        IpAddress::Ipv6(v6_addr) => {
            match netmask {
                IpAddress::Ipv6(v6_netmask) => {
                    let v6_cidr = ipv6_cidr_from_ipv6_mask(Ipv6Addr::from(v6_addr), Ipv6Addr::from(v6_netmask))?;
                    Ok(IpCidr::Ipv6(v6_cidr))
                },
                _ => Err(smoltcp::Error::Illegal)
            }
        },
        _ => unreachable!()
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Interface {
    name : String,
    index: u32,
    flags: Flags,
    mtu  : u32,
    hwaddr: Option<EthernetAddress>,
    dstaddr: Option<IpCidr>,
    addrs: Vec<IpCidr>,
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
        self.flags.contains(Flags::IFF_BROADCAST)
    }

    pub fn is_tun(&self) -> bool {
        !self.is_loopback() 
        && !self.is_tap()
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

    pub fn dstaddr(&self) -> Option<IpCidr> {
        self.dstaddr
    }

    pub fn addrs(&self) -> &Vec<IpCidr> {
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
        for ip_cidr in self.addrs.iter() {
            match ip_cidr {
                &IpCidr::Ipv4(ipv4_cidr) => {
                    write!(f, "\n    inet {}", ipv4_cidr)?;
                    if self.flags.contains(Flags::IFF_POINTOPOINT) && self.dstaddr.is_some() {
                        write!(f, " --> {}", self.dstaddr.unwrap())?;
                    }
                    write!(f, " netmask {}", ipv4_cidr.netmask())?;
                    if self.flags.contains(Flags::IFF_BROADCAST) {
                        write!(f, " broadcast {}", ipv4_cidr.broadcast().unwrap())?;
                    }
                }
                &IpCidr::Ipv6(ipv6_cidr) => {
                    write!(f, "\n    inet6 {}", ipv6_cidr)?;
                    if self.flags.contains(Flags::IFF_POINTOPOINT) && self.dstaddr.is_some() {
                        write!(f, " --> {}", self.dstaddr.unwrap())?;
                    }
                }
                _ => { unreachable!() }
            }
        }

        Ok(())
    }
}

fn fill(ifaddr: &InterfaceAddress, iface: &mut Interface){
    if ifaddr.address.is_some() {
        let sock_addr = ifaddr.address.unwrap();
        match sock_addr {
            SockAddr::Inet(inet_addr) => {
                let std_ip = inet_addr.to_std().ip();

                let netmask = match ifaddr.netmask {
                    Some(inet) => match inet {
                        SockAddr::Inet(inet_addr) => inet_addr.to_std().ip(),
                        _ => { unreachable!() }
                    },
                    None => {
                        if std_ip.is_ipv4() {
                            IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255))
                        } else if std_ip.is_ipv6() {
                            IpAddr::V6(Ipv6Addr::new(0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff))
                        } else {
                            unreachable!()
                        }
                    },
                };

                iface.addrs.push(ip_cidr_from_netmask(IpAddress::from(std_ip), IpAddress::from(netmask)).unwrap());
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
                iface.hwaddr = Some(EthernetAddress(link_addr.addr()));
            }
        }
    }

    if ifaddr.destination.is_some() {
        let sock_addr = ifaddr.destination.unwrap();
        match sock_addr {
            SockAddr::Inet(inet_addr) => {
                let std_ip = inet_addr.to_std().ip();

                let netmask = match ifaddr.netmask {
                    Some(inet) => match inet {
                        SockAddr::Inet(inet_addr) => inet_addr.to_std().ip(),
                        _ => { unreachable!() }
                    },
                    None => {
                        if std_ip.is_ipv4() {
                            IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255))
                        } else if std_ip.is_ipv6() {
                            IpAddr::V6(Ipv6Addr::new(0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff))
                        } else {
                            unreachable!()
                        }
                    },
                };

                let ip_cidr = ip_cidr_from_netmask(IpAddress::from(std_ip), IpAddress::from(netmask)).unwrap();

                iface.dstaddr = Some(ip_cidr);
            },
            _ => {}
        }
    }
}

pub fn interfaces() -> Vec<Interface> {
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
                name     : name.clone(),
                index    : if_index as u32,
                flags    : ifaddr.flags,
                mtu      : if_mtu as u32,
                hwaddr   : None,
                dstaddr  : None,
                addrs    : vec![],
            };
            fill(&ifaddr, &mut iface);
            ifaces.push(iface);
        }
    }

    ifaces
}


