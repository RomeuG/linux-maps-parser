use linux_maps_parser::parse;
use std::process;

fn main() {
    let pid = process::id();
    match parse(pid) {
        Ok(p) => println!("{:?}", p),
        Err(e) => println!("Error while parsing: {:?}", e),
    }
}
