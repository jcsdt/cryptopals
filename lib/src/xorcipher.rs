use std;
use std::f32;

use base64;
use hex;

use common;

pub fn crack_single_xor(input: &str) -> Result<(Option<String>, usize), hex::FromHexError> {
   let decoded = try!(hex::decode(input));

   let (out, score) = crack_single_xor_bytes(&decoded);
   return Ok((String::from_utf8(out).ok(), score));
}

fn crack_single_xor_bytes(decoded: &[u8]) -> (Vec<u8>, usize) {
   let mut max_score = 0;
   let mut candidate_string = vec![];
let len_input = decoded.len();
   // Test all ASCII values
   for k in 0u8..255 {
        let key = std::iter::repeat(k).take(len_input).collect::<Vec<u8>>();

        let xored = common::xor_bytes(&decoded, &key);
        let score = score_eng(&xored);

        if score > max_score {
            max_score = score;
            // Can't panic here since score > 0
            candidate_string = xored.clone();
        }
   }

   (candidate_string, max_score)
}

fn score_eng(input: &[u8]) -> usize {
    let mut score = 0;
    let most_common_letters = &vec![b'e', b't', b'a', b'o', b'i', b'n', b' ', b's', b'h', b'r', b'd', b'l', b'u'];
    let number_of_letters = most_common_letters.len();
    for c in input {
        let mut idx = 0;
        for r in most_common_letters {
            if r == c || r.to_ascii_uppercase() == *c {
                score += number_of_letters - idx;
            }

            idx += 1;
        }
    }

    score
}

pub fn detect_single_xor(input: &str) -> Result<String, hex::FromHexError> {
    let mut max_score = 0;
    let mut candidate_string = String::new();

    for s in input.split("\n") {
        let (out, score) = try!(crack_single_xor(s));

        if out.is_some() && score > max_score {
            max_score = score;
            candidate_string = out.unwrap().clone();
        }
    }

    Ok(candidate_string)
}

pub fn repeating_xor_cipher(input: &str, key: &str) -> Vec<u8> {
   let input = input.as_bytes();
   let key = key.bytes().cycle().take(input.len()).collect::<Vec<u8>>();
   common::xor_bytes(input, &key)
}

pub fn crack_repeating_xor(input: &str) -> Result<String, base64::DecodeError> {
    let input = try!(base64::decode(input));

    let mut best_key_size = 0;
    let mut min_dist: f32 = f32::MAX;

    let size = input.len() as u32;
    for key_size in 2u32..40 {
        let iter = input.as_slice().chunks(key_size as usize);
        let sum_dist: f32 = iter.clone().zip(iter.skip(1))
            .filter(|&(a,b)| a.len() == b.len())
            .map(|(a,b)| hamming_distance(a, b) as f32 / key_size as f32)
            .sum();

        let avg_dist: f32 = sum_dist as f32 / (size / key_size) as f32;

        if avg_dist < min_dist {
            min_dist = avg_dist;
            best_key_size = key_size;
        }
    }

    let mut result = Vec::with_capacity(input.len());
    result.resize(input.len(), 0);
    for i in 0..best_key_size {
        let block = input.iter()
            .enumerate()
            .filter(|&(idx, _v)| idx as u32 % best_key_size == i)
            .map(|(_idx, v)| *v)
            .collect::<Vec<u8>>();
        let (deciphered_block, _) = crack_single_xor_bytes(&block[..]);
        for (idx, u) in deciphered_block.iter().enumerate() {
            result[idx * (best_key_size as usize) + (i as usize)] = *u;
        }
    }

    Ok(String::from_utf8(result).unwrap())
}

fn hamming_distance(a: &[u8], b: &[u8]) -> u32 {
    common::xor_bytes(a, b).iter().map(|b| b.count_ones()).sum()
}

#[cfg(test)]
mod tests {

    use super::*;

    use std::fs::File;
    use std::io::prelude::*;

    #[test]
    fn test_crack_single_xor() {
        println!("{:?}", crack_single_xor("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736").unwrap().0)
    }

    #[test]
    fn test_detect_single_xor() {
        let mut f = File::open("./data/4.txt").expect("file not found");

        let mut contents = String::new();
        f.read_to_string(&mut contents).expect("something went wrong reading the file");

        println!("{}", detect_single_xor(&contents).unwrap());
    }

    #[test]
    fn test_repeating_xor_cipher() {
        assert_eq!(
            hex::encode(repeating_xor_cipher("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal", "ICE")),
            "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
        )
    }

    #[test]
    fn test_hamming_distance() {
        assert_eq!(
            hamming_distance("this is a test".as_bytes(), "wokka wokka!!!".as_bytes()),
            37
        )
    }

    #[test]
    fn test_crack_repeating_xor() {
        let mut f = File::open("./data/6.txt").expect("file not found");

        let mut contents = String::new();
        f.read_to_string(&mut contents).expect("something went wrong reading the file");

        println!("{}", crack_repeating_xor(&str::replace(&contents, "\n", "")).unwrap());
    }
}
