extern crate znet;

use std::net::IpAddr;


fn main (){
    let network_global = znet::dns::get_network_global();
    println!("NetworkGlobal: {:?}", network_global);
    
    // 设置全局 DNS, 需要 Root 权限
    // network_global.set_global_dns("8.8.4.4".parse::<IpAddr>().unwrap());

    for service in znet::dns::list_network_services_order() {
        println!("NetworkService: {:?}\n\n", service);
    }
    
    println!("{:?}", znet::dns::list_network_interfaces());

    println!("{:?}", network_global.service.dns());

    let dns_ip = "8.8.4.4".parse::<IpAddr>().unwrap();
    
    println!("Set DNS: {:?}", network_global.service.set_dns(&[dns_ip]));
    println!("{:?}", network_global.service.dns());
}