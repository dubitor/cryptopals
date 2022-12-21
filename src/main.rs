mod set1;
fn main() {
    let file = reqwest::blocking::get("https://www.cryptopals.com/static/challenge-data/6.txt")
        .unwrap()
        .text()
        .unwrap();
    let input = base64::decode(file.replace('\n', "")).unwrap();
    let plaintext = set1::break_repeating_key_xor(&input);
    println!("{}", String::from_utf8(plaintext).unwrap());
}
