use std::io::{self, Read};

fn main() {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input).unwrap();

    let lines = if input.is_empty() {
        0
    } else {
        let newline_count = input.iter().filter(|&&byte| byte == b'\n').count();
        newline_count + usize::from(input.last() != Some(&b'\n'))
    };

    println!("[{lines},{}]", input.len());
}
