use base64;
use core::num;
use hex;
use std::cmp::Ordering;
use std::collections::{BTreeMap, BinaryHeap, HashMap};

// Lewand's order, according to wikipedia, with space added as most common, and '!' used
// as a stand-in for all non-alphabetic chars
static LEWAND_ENGLISH_CHAR_FREQUENCY_ORDER: &str = " etaoinshrdlcumwfgypbvkjxqz*";

fn hex_to_base64(hex_string: String) -> String {
    let bytes = hex::decode(hex_string).expect("invalid hex");
    base64::encode(bytes)
}

// The xor combination of two same-length buffers.
fn fixed_xor(buf1: &Vec<u8>, buf2: &Vec<u8>) -> Result<Vec<u8>, &'static str> {
    if buf1.len() != buf2.len() {
        return Err("Cannot xor buffers of differnt lengths");
    }
    Ok(buf1
        .iter()
        .zip(buf2.iter())
        .map(|(b1, b2)| b1 ^ b2)
        .collect())
}

// The xor combination of a buffer with a single character
fn single_char_xor(buf: &Vec<u8>, ascii_char: u8) -> Vec<u8> {
    buf.iter().map(|b| b ^ ascii_char).collect()
}

#[derive(Eq)]
struct DecryptionAttempt {
    plaintext: Vec<u8>,
    confidence_score: u32, // the lower the score, the higher the confidence
}

impl Ord for DecryptionAttempt {
    fn cmp(&self, other: &Self) -> Ordering {
        other.confidence_score.cmp(&self.confidence_score)
    }
}

impl PartialOrd for DecryptionAttempt {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for DecryptionAttempt {
    fn eq(&self, other: &Self) -> bool {
        self.confidence_score == other.confidence_score
    }
}


// Get confidence score of decryption attempt based on English character frequency analysis
// First, the numerical frequency of every byte is calculated.
// The frequencies are normalised, with the totals for lower- and upper-case versions of the same letter combined
// and the totals for all non-alphabetic characters combined
// For each character in the letter range, the frequency is combined with a benchmark
// 0 points are awarded if the relative frequency corresponds with the benchmark, 1 if it's off by one, and so forth.
fn calculate_confidence_score(plaintext: &Vec<u8>) -> u32 {
    // benchmark_frequencies.get(c) is the relative frequency of char c in the benchmark
    let mut benchmark_rel_frequencies = HashMap::new();
    // LEWAND_ENGLISH_CHAR_FREQUENCY_ORDER
    //     .as_bytes()
    //     .iter()
    //     .enumerate()
    //     .for_each(|(i, c)| benchmark_rel_frequencies.insert(*c, i as i32));
    for (i, c) in LEWAND_ENGLISH_CHAR_FREQUENCY_ORDER
        .as_bytes()
        .iter()
        .enumerate() {
            let _res = benchmark_rel_frequencies.insert(*c, i as i32);
        }

    let num_frequencies = get_character_frequencies(&plaintext);

    println!("num_frequencies: {:?}", num_frequencies);

    // sort into order of relative frequencies
    let mut rel_frequencies: Vec<(&u8, &i32)> = num_frequencies.iter().collect();
    rel_frequencies.sort_by(|a, b| b.1.cmp(a.1));

    println!("{:?}", rel_frequencies); // debugging
    // calculate the score, by subtracting the rel frequency of each char in our sample with that
    // of the same char in the benchmark (absolute difference), then summing the results
    let mut score = 0;
    for (position, entry) in rel_frequencies.iter().enumerate() {
        let byte = *entry.0;
        score += (position as i32 - benchmark_rel_frequencies.get(&byte).unwrap()).abs() as u32;
    }
    score
    // rel_frequencies
    //     .values()
    //     .enumerate()
    //     .map(|(freq, character)| (benchmark_rel_frequencies.get(character).unwrap() - freq as i32).abs() as u32)
    //     .sum()
}

// Given ASCII text, return normalised numerical frequencies, adding uppercase totals to lowercase ones, 
// and other non-alphabetic chars to '*'
fn get_character_frequencies(text: &Vec<u8>) -> HashMap<u8, u64> {
    let mut num_frequencies = HashMap::new();
    for byte in text.to_ascii_lowercase().iter() {
        let adjusted_char = match *byte {
            b' ' => b' ', // space
            non_alpha if !non_alpha.is_ascii_lowercase() => b'*',
            _ => *byte,
        };
        if !num_frequencies.contains_key(&adjusted_char) {
            num_frequencies.insert(adjusted_char, 1);
        } else {
            *num_frequencies.get_mut(&adjusted_char).unwrap() += 1;
        }
    }
    num_frequencies

}
// Decode a piece of English cypher text that's been xor'd against a single ASCII char
fn solve_single_byte_xor_cipher(cipher_text: Vec<u8>) -> Vec<u8> {
    let mut heap = BinaryHeap::new();
    // For each ascii character:
    //      xor it against the cypher text to get a plaintext version
    //      calculate a score of the plaintext version using char frequency
    //      add plaintext version to priority heap using score as key
    // return the version at the top of the heap
    for ascii_char in 0u8..=126 {
        let plaintext = single_char_xor(&cipher_text, ascii_char);
        let confidence_score = calculate_confidence_score(&plaintext);

        // debugging
        println!("{}", String::from_utf8(plaintext.clone()).unwrap());
        println!("acii char = {ascii_char}, confidence score = {confidence_score}");
        println!();

        heap.push(DecryptionAttempt {
            plaintext,
            confidence_score,
        });
    }
    heap.pop().unwrap().plaintext
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_to_base64_example() {
        let input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
        let actual = hex_to_base64(input.into());
        assert_eq!(actual, expected);
    }

    #[test]
    fn fixed_xor_example() {
        let buf1 = hex::decode("1c0111001f010100061a024b53535009181c".as_bytes()).unwrap();
        let buf2 = hex::decode("686974207468652062756c6c277320657965".as_bytes()).unwrap();
        let expected: String = "746865206b696420646f6e277420706c6179".to_string();

        let bytes = fixed_xor(&buf1, &buf2).unwrap();
        let actual = hex::encode(bytes);
        assert_eq!(actual, expected);
    }

    #[test]
    fn single_byte_xor_cipher_example() {
        let input = hex::decode(
            "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736".as_bytes(),
        )
        .unwrap();
        let solution = solve_single_byte_xor_cipher(input);
        println!("{}", String::from_utf8(solution).unwrap());
    }
}
