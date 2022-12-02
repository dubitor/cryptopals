use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap};
use std::error::Error;

// Lewand's order, according to wikipedia, with space added as most common, and '!' used
// as a stand-in for all non-alphabetic chars
static LEWAND_ENGLISH_CHAR_FREQUENCY_ORDER: &str = " etaoinshrdlcumwfgypbvkjxqz*";

type CharFreq = HashMap<u8, u64>;
type CharPercent = HashMap<u8, f64>;
type ConfidenceScore = u32;

fn hex_to_base64(hex_string: String) -> String {
    let bytes = hex::decode(hex_string).expect("invalid hex");
    base64::encode(bytes)
}

// The xor combination of two same-length buffers.
fn fixed_xor(buf1: &[u8], buf2: &[u8]) -> Result<Vec<u8>, &'static str> {
    if buf1.len() != buf2.len() {
        return Err("Cannot xor buffers of different lengths");
    }
    Ok(buf1
        .iter()
        .zip(buf2.iter())
        .map(|(b1, b2)| b1 ^ b2)
        .collect())
}

// The xor combination of a buffer with a single character
fn single_char_xor(buf: &[u8], ascii_char: u8) -> Vec<u8> {
    buf.iter().map(|b| b ^ ascii_char).collect()
}

#[derive(Eq)]
struct DecryptionAttempt {
    plaintext: Vec<u8>,
    confidence_score: ConfidenceScore, // the lower the score, the higher the confidence
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
// Benchmark is complete works of shakespeare
// First, the frequency of each character is calculated as the percentage of the total characters
// Non-alphabetic chars (except space) are treated as alike
// These percentages are then compared with the benchmark to generate a score
fn calculate_confidence_score(
    plaintext: &[u8],
    bench_percent_freqs: &CharPercent,
) -> ConfidenceScore {
    let num_frequencies = get_character_frequencies(plaintext);
    let percent_freqs = percent_freqs_from_num_freqs(num_frequencies, plaintext.len());

    let mut score = 0;
    // For each character, get the difference of its percentage frequency in benchmark and plaintext
    for char in bench_percent_freqs.keys() {
        let diff =
            (bench_percent_freqs.get(char).unwrap() - percent_freqs.get(char).unwrap()).abs();
        // Convert it to an int between 0 and 1000 - this enables us to use it as a key later (floats don't implement Eq)
        let diff = (diff * 10.0) as u32;
        score += diff;
    }
    score
}

// Given ASCII text, return normalised numerical frequencies, adding uppercase totals to lowercase ones,
// and other non-alphabetic chars to '*'
fn get_character_frequencies(text: &[u8]) -> CharFreq {
    let mut num_frequencies = initialise_char_freq_map();
    for byte in text.to_ascii_lowercase().iter() {
        let adjusted_char = match *byte {
            b' ' => b' ', // space
            non_alpha if !non_alpha.is_ascii_lowercase() => b'*',
            _ => *byte,
        };
        *num_frequencies.get_mut(&adjusted_char).unwrap() += 1;
    }
    num_frequencies
}

fn initialise_char_freq_map() -> CharFreq {
    let mut map = CharFreq::new();
    for char in LEWAND_ENGLISH_CHAR_FREQUENCY_ORDER.as_bytes().iter() {
        map.insert(*char, 0);
    }
    map
}

fn percent_freqs_from_num_freqs(char_freqs: CharFreq, size: usize) -> CharPercent {
    char_freqs
        // Transform into iterator of (char, num) pairs
        .keys()
        .map(|char| char_freqs.get_key_value(char).unwrap())
        // Transfrom each (char, num) pair into a (char, percentage) pair
        .map(|(char, num)| (*char, (*num as f64 / size as f64) * 100.0))
        .collect()
}

fn get_benchmark_percentage_frequencies() -> CharPercent {
    let benchmark_text = complete_works_shakespeare().unwrap();
    let size = benchmark_text.len();
    let char_freqs = get_character_frequencies(&benchmark_text);
    percent_freqs_from_num_freqs(char_freqs, size)
}

fn complete_works_shakespeare() -> Result<Vec<u8>, Box<dyn Error>> {
    let text =
        reqwest::blocking::get("https://www.gutenberg.org/cache/epub/100/pg100.txt")?.text()?;
    Ok(text.into_bytes())
}

// For each ascii character:
//      xor it against the cypher text to get a plaintext version
//      calculate a score of the plaintext version using char frequency
//      add plaintext version to priority heap using score as key
fn add_xor_decrytion_attempts_to_heap(
    cipher_text: &[u8],
    benchmark: &CharPercent,
    heap: &mut BinaryHeap<DecryptionAttempt>,
) {
    for ascii_char in 0u8..=126 {
        let plaintext = single_char_xor(cipher_text, ascii_char);
        let confidence_score = calculate_confidence_score(&plaintext, benchmark);

        heap.push(DecryptionAttempt {
            plaintext,
            confidence_score,
        });
    }
}
// Decode a piece of English cypher text that's been xor'd against a single ASCII char
fn solve_single_byte_xor_cipher(cipher_text: Vec<u8>) -> Vec<u8> {
    let mut heap: BinaryHeap<DecryptionAttempt> = BinaryHeap::new();
    let benchmark = get_benchmark_percentage_frequencies();
    add_xor_decrytion_attempts_to_heap(&cipher_text, &benchmark, &mut heap);
    heap.pop().unwrap().plaintext
}

// Finds and decodes the line that has been encoded
fn detect_single_char_xor(lines: Vec<Vec<u8>>) -> Vec<u8> {
    let benchmark = get_benchmark_percentage_frequencies();
    // for each line:
    //      for each letter:
    //          calculate confidence score and plaintext
    //      get highest confidence score and plaintext and add to heap
    // return line with highest confidence score
    let mut lines_heap = BinaryHeap::new();
    for line in lines {
        let mut heap = BinaryHeap::new();
        add_xor_decrytion_attempts_to_heap(&line, &benchmark, &mut heap);
        let best = heap.pop().unwrap();
        lines_heap.push(best);
    }
    lines_heap.pop().unwrap().plaintext
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
        let actual = String::from_utf8(solution).unwrap();
        let expected = "Cooking MC's like a pound of bacon".to_string();
        assert_eq!(actual, expected);
    }

    #[test]
    fn detect_single_char_xor_example() {
        let file = reqwest::blocking::get("https://www.cryptopals.com/static/challenge-data/4.txt")
            .unwrap()
            .text()
            .unwrap();
        let input = file
            .lines()
            .map(|line| hex::decode(line.as_bytes()).unwrap())
            .collect();
        let plaintext = detect_single_char_xor(input);
        let actual = String::from_utf8(plaintext).unwrap();
        let expected = "Now that the party is jumping\n".to_string();
        assert_eq!(actual, expected);
    }
}
