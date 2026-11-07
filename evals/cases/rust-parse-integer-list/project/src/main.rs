use std::io::{self, Read};

fn main() {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).unwrap();
    let values: Result<Vec<i32>, _> = input.split_whitespace().map(str::parse).collect();
    match values {
        Ok(v) => println!("[{}]", v.iter().map(ToString::to_string).collect::<Vec<_>>().join(",")),
        Err(_) => println!("\"error\""),
    }
}
