use std::io::{self, Read};

fn main() {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).unwrap();

    match input.trim().parse::<u64>() {
        Ok(seconds) => println!("\"{:02}:{:02}:{:02}\"", seconds / 3600, (seconds / 60) % 60, seconds % 60),
        Err(_) => println!("\"error\""),
    }
}
