extern crate net2;

fn main (){
    println!("{:?}", net2::dns::get_network_global());
    
    for service in net2::dns::list_network_services_order() {
        println!("{:?}\n\n", service);
    }
    
    println!("{:?}", net2::dns::list_network_interfaces());
}