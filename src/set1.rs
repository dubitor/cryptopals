fn hex_to_base64(hex: &Vec<u8>) -> Vec<u8> {
    vec![0]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge1() {
        let hex: Vec<u8> = Vec::from_hex("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d").except("Invalid hex string");
        println!("{:?}", hex);
    }
}