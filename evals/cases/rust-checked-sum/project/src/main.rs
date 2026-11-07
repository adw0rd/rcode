use std::io::{self, Read};
fn main() {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).unwrap();
    let mut sum: i64 = 0;
    for token in input.split_whitespace() {
        match token.parse::<i64>() {
            Ok(n) => sum += n,
            Err(_) => { println!("\"error\""); return; }
        }
    }
    println!("{}", sum);
}
