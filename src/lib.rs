#[macro_use]
extern crate log;
#[macro_use]
extern crate cfg_if;

#[cfg(unix)]
extern crate libc;
#[cfg(unix)]
extern crate nix;

extern crate smoltcp;

cfg_if! {
    if #[cfg(target_os = "macos")] {
        extern crate core_foundation;
        extern crate system_configuration;
    }
}


pub mod sys;


#[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "linux"))]
pub mod interface;

#[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "linux"))]
pub mod raw_socket;

#[cfg(any(target_os = "macos"))]
pub mod dns;

#[cfg(any(target_os = "macos"))]
pub mod route;
