use std::io::{self, Read};

fn main() {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input).unwrap();

    let mut encoded = String::with_capacity(input.len() * 2);
    for byte in input {
        use std::fmt::Write;
        write!(&mut encoded, "{byte:02x}").unwrap();
    }

    println!("\"{encoded}\"");
}
