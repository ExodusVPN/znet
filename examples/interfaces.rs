extern crate net2;

use std::env;

fn main(){
    let mut args = env::args();
    let _ = args.next().unwrap();

    if let Some(ifname) = args.next() {
        let iface = net2::interface::Interface::with_name(&ifname).unwrap();
        println!("{}", iface);
    } else {
        let ifaces = net2::interface::interfaces();
        for x in ifaces{
            println!("{}\n", x);
        }
    }
}