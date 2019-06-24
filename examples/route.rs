extern crate net2;


fn main() {
    for msg in net2::route::iter().unwrap() {
        println!("{:?}  -->  {:?}", msg.dest, msg.gateway);
    }
}