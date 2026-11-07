use std::io::{self, Read};

fn main() {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).unwrap();

    let values: Result<Vec<i64>, _> = input.split_whitespace().map(str::parse).collect();
    let values = match values {
        Ok(values) => values,
        Err(_) => {
            println!("\"error\"");
            return;
        }
    };

    match values.into_iter().try_fold(0_i64, i64::checked_add) {
        Some(sum) => println!("{sum}"),
        None => println!("\"overflow\""),
    }
}
