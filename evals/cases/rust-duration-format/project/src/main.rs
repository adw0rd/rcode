use std::io::{self, Read};
fn main() {
    let mut s = String::new();
    io::stdin().read_to_string(&mut s).unwrap();
    match s.trim().parse::<u64>() {
        Ok(n) => println!("\"{:02}:{:02}:{:02}\"", n / 3600 % 24, n / 60 % 60, n % 60),
        Err(_) => println!("\"error\""),
    }
}
