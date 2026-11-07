use std::io::{self, Read};

fn main() {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).unwrap();

    let line = input.strip_suffix('\n').unwrap_or(&input);
    println!("{}", line.chars().count());
}
