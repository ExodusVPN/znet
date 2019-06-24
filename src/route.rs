use crate::sys;


use std::ptr;
use std::mem;
use std::io;

pub fn add() {

}

pub fn remove() {

}



#[derive(Debug, Copy, Clone)]
pub enum RouteAddr {
    V4(std::net::SocketAddrV4),
    V6(std::net::SocketAddrV6),
    Unix(nix::sys::socket::UnixAddr),
    // Linux: sockaddr_ll
    // macOS: sockaddr_dl
    Link(nix::sys::socket::LinkAddr),
    // TODO:
    // Linux/Android Netlink ?
    // sys::sockaddr_nl
    // SysControl ?
}


#[derive(Debug, Copy, Clone)]
pub struct RouteTableMessage {
    pub hdr: sys::rt_msghdr,
    pub dest: RouteAddr,
    pub gateway: RouteAddr,
}


unsafe fn sa_to_addr(sa: *mut sys::sockaddr) -> (RouteAddr, *mut u8) {
    match (*sa).sa_family as i32 {
        sys::AF_INET => {
            let sa_in = sa as *mut sys::sockaddr_in;
            let sa_in_addr = (*sa_in).sin_addr.s_addr;
            let sa_in_port = (*sa_in).sin_port;
            let ipv4_addr = std::net::Ipv4Addr::from(sa_in_addr);
            let socket_addr = std::net::SocketAddrV4::new(ipv4_addr, sa_in_port);

            (RouteAddr::V4(socket_addr), sa_in as _)

        },
        sys::AF_INET6 => {
            let sa_in = sa as *mut sys::sockaddr_in6;
            let sa_in_addr = (*sa_in).sin6_addr.s6_addr;
            let sa_in_port = (*sa_in).sin6_port;
            let sa_flowinfo = (*sa_in).sin6_flowinfo;
            let sa_scope_id = (*sa_in).sin6_scope_id;
            
            let ipv6_addr = std::net::Ipv6Addr::from(sa_in_addr);

            let socket_addr = std::net::SocketAddrV6::new(ipv6_addr, sa_in_port, sa_flowinfo, sa_scope_id);

            (RouteAddr::V6(socket_addr), sa_in as _)
        },
        sys::AF_UNIX => {
            println!("sa_len: {:?} sa_family: {:?} sa_data: {:?}",
                (*sa).sa_len,
                (*sa).sa_family,
                mem::transmute::<[sys::c_char; 14], [u8; 14]>((*sa).sa_data),
                );
            unimplemented!()
        },
        sys::AF_LINK => {
            println!("sa_len: {:?} sa_family: {:?} sa_data: {:?}",
                (*sa).sa_len,
                (*sa).sa_family,
                mem::transmute::<[sys::c_char; 14], [u8; 14]>((*sa).sa_data),
                );
            unimplemented!()
        },
        _ => unreachable!(),
    }
}


fn req(family: sys::c_int, flags: sys::c_int) -> Result<(*mut u8, usize), io::Error> {
    let mut mib: [sys::c_int; 6] = [0; 6];
    let mut lenp: sys::size_t = 0;

    mib[0] = sys::CTL_NET;
    mib[1] = sys::AF_ROUTE;
    mib[2] = 0;
    mib[3] = family; // only addresses of this family
    mib[4] = sys::NET_RT_DUMP;
    mib[5] = flags;  // not looked at with NET_RT_DUMP

    let mib_ptr = &mib as *const sys::c_int as *mut sys::c_int;

    if unsafe { sys::sysctl(mib_ptr, 6, ptr::null_mut(), &mut lenp, ptr::null_mut(), 0) } < 0 {
        return Err(io::Error::last_os_error());
    }

    let mut buf: Vec<sys::c_char> = Vec::with_capacity(lenp as usize);
    let buf_ptr: *mut u8 = buf.as_mut_ptr() as _;
    if unsafe { sys::sysctl(mib_ptr, 6, buf_ptr as _, &mut lenp, ptr::null_mut(), 0) } < 0 {
        return Err(io::Error::last_os_error());
    }

    if buf_ptr.is_null() {
        return Err(io::Error::last_os_error());
    }

    Ok((buf_ptr, lenp))
}

pub fn iter() -> Result<RouteTableMessageIter, io::Error> {
    // let family = sys::AF_INET;
    // let family = sys::AF_INET6;
    let family = 0;  // inet4 & inet6
    let flags = 0;
    let (buf_ptr, len) = req(family, flags)?;

    let end_ptr = unsafe { buf_ptr.add(len) };

    Ok(RouteTableMessageIter {
        buf_ptr,
        len,
        end_ptr,
    })
}


pub struct RouteTableMessageIter {
    buf_ptr: *mut u8,
    #[allow(dead_code)]
    len: usize,
    end_ptr: *mut u8,
}

impl Iterator for RouteTableMessageIter {
    type Item = RouteTableMessage;

    fn next(&mut self) -> Option<Self::Item> {
        if self.buf_ptr >= self.end_ptr {
            return None;
        }

        unsafe {
            let rtm = self.buf_ptr as *mut sys::rt_msghdr;
            let rtm_msglen = (*rtm).rtm_msglen as usize;

            let sa = rtm.add(1) as *mut sys::sockaddr;
            let (dest, sa) = sa_to_addr(sa);
            let sa = sa as *mut sys::sockaddr;

            let (gateway, _sa) = sa_to_addr(sa);
            self.buf_ptr = self.buf_ptr.add(rtm_msglen);

            Some(RouteTableMessage {
                hdr: *rtm,
                dest,
                gateway,
            })
        }
    }
}


pub fn list() -> Result<Vec<RouteTableMessage>, io::Error> {
    iter().map(|handle| handle.collect::<Vec<_>>())
}
