extern crate znet;

use std::env;

fn main(){
    let mut args = env::args();
    let _ = args.next().unwrap();
    
    if let Some(ifname) = args.next() {
        let iface = znet::interface::Interface::with_name(&ifname).unwrap();
        println!("{}", iface);
    } else {
        let ifaces = znet::interface::interfaces();
        for x in ifaces{
            println!("{}\n", x);
        }
    }
}