use std::io::{self, Read};

fn main() {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).unwrap();

    let values: Result<Vec<i32>, _> = input
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter(|token| !token.is_empty())
        .map(str::parse)
        .collect();

    match values {
        Ok(values) => println!("[{}]", values.iter().map(ToString::to_string).collect::<Vec<_>>().join(",")),
        Err(_) => println!("\"error\""),
    }
}
