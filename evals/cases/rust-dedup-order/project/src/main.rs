use std::collections::HashSet;
use std::io::{self, Read};

fn main() {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).unwrap();
    let mut seen = HashSet::new();
    let mut values = Vec::new();
    for token in input.split_whitespace() {
        if let Ok(n) = token.parse::<i64>() {
            if seen.insert(n) { values.push(n); }
        }
    }
    values.sort();
    println!("[{}]", values.iter().map(ToString::to_string).collect::<Vec<_>>().join(","));
}
