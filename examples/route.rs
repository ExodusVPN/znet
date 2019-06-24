extern crate znet;


fn main() {
    for msg in znet::route::iter().unwrap() {
        println!("{:?}  -->  {:?}", msg.dest, msg.gateway);
        println!("{:?}", msg.hdr);
    }
}