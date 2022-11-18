use base64;
use hex::FromHex;
use std::str;
fn main() {
    println!("hello, world!");
}
fn hex_to_base64(hex: &[char]) -> String {
    let bytes = hex::decode(hex).expect("Invalid hex bytes");
    base64::encode(bytes)
}

fn hex_str_to_hex(hex_str: &str) -> Vec<char> {
    hex_str
        .chars()
        .map(|c| std::char::from_u32(c as u32 - '0' as u32).expect("not ascii"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge1() {
        let hex_str ="49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let hex = hex_str_to_hex(hex_str);
        let base64 = hex_to_base64(&hex);
        assert_eq!(
            base64,
            "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t".to_string()
        );
    }
}
