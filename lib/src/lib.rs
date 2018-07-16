#![feature(iterator_flatten)]
use std::f32;
use std::collections::HashMap;

extern crate base64;
extern crate hex;
extern crate crypto;

use crypto::{ buffer };
use crypto::buffer::{ ReadBuffer, WriteBuffer, BufferResult };

pub fn hex2base64(input: &str) -> Result<String, hex::FromHexError> {
    let b = hex::decode(input);
    b.map(|r| base64::encode(&r))
}

fn xor_bytes(l: &[u8], r: &[u8]) -> Vec<u8> {
    l.iter().zip(r.iter()).map(|(x, y)| x ^ y).collect()
}

pub fn xor(a: &str, b: &str) -> Result<Vec<u8>, hex::FromHexError> {
    let l = try!(hex::decode(a));
    let r = try!(hex::decode(b));
    Ok(xor_bytes(&l, &r))
}

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

        let xored = xor_bytes(&decoded, &key);
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
   xor_bytes(input, &key)
}

pub fn hamming_distance(a: &[u8], b: &[u8]) -> u32 {
    xor_bytes(a, b).iter().map(|b| b.count_ones()).sum()
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

pub fn decrypt_aes_ecb_128(input: &[u8], key: &[u8]) -> Result<Vec<u8>, crypto::symmetriccipher::SymmetricCipherError> {
    let mut decryptor = crypto::aes::ecb_decryptor(crypto::aes::KeySize::KeySize128, key, crypto::blockmodes::NoPadding);

    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(input);
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    loop {
        let result = try!(decryptor.decrypt(&mut read_buffer, &mut write_buffer, true));
        final_result.extend(write_buffer.take_read_buffer().take_remaining().iter().map(|&i| i));
        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => { }
        }
    }

    Ok(final_result)
}

pub fn encrypt_aes_ecb_128(input: &[u8], key: &[u8]) -> Result<Vec<u8>, crypto::symmetriccipher::SymmetricCipherError> {
    let mut encryptor = crypto::aes::ecb_encryptor(crypto::aes::KeySize::KeySize128, key, crypto::blockmodes::NoPadding);

    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(input);
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    loop {
        let result = try!(encryptor.encrypt(&mut read_buffer, &mut write_buffer, true));
        final_result.extend(write_buffer.take_read_buffer().take_remaining().iter().map(|&i| i));
        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => { }
        }
    }

    Ok(final_result)
}

pub fn decrypt_aes_cbc_128(input: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, crypto::symmetriccipher::SymmetricCipherError> {
    let iter = input.chunks(16).map(|c| decrypt_aes_ecb_128(c, key).unwrap());
    let result = iter.zip(std::iter::once(iv).chain(input.chunks(16))).map(|(a, b)| xor_bytes(a.as_slice(), b)).flatten().collect();
    Ok(result)
}

pub fn encrypt_aes_cbc_128(input: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, crypto::symmetriccipher::SymmetricCipherError> {
    let mut result = Vec::<u8>::new();
    let mut to_xor = iv.to_vec();

    for c in input.chunks(16) {
        let mut ciphered = try!(encrypt_aes_ecb_128(&xor_bytes(c, to_xor.as_slice()), key));
        to_xor = ciphered.clone();
        result.append(&mut ciphered);
    }

    Ok(result)
}

fn count_repeating_blocks(input: Vec<u8>) -> u32  { 
    let mut map : HashMap<&[u8], u32> = HashMap::new();
    for i in 0..input.len() / 16 {
        let s = &input[i * 16 .. (i+1) * 16];
        let c = map.entry(s).or_insert(0);
        *c += 1;
    }

    *map.values().max().unwrap_or(&0)
}

pub fn detect_aes_ecb_128(input: &str) -> Result<String, hex::FromHexError> {
    let mut max_score = 0;
    let mut candidate_string = "";

    for s in input.split("\n") {
        let score = count_repeating_blocks(try!(hex::decode(s)));
        if score > max_score {
            max_score = score;
            candidate_string = s.clone();
        }
    }

    Ok(candidate_string.to_string())
}

pub fn pkcs7(input: &[u8], size: usize) -> Vec<u8> {
    let input_size = input.len();
    let diff = size - input_size;

    let mut result = Vec::with_capacity(size);
    result.extend_from_slice(input);
    result.append(&mut vec![diff as u8; diff]);
    result
}

#[cfg(test)]
mod tests {

    use super::*;

    use std::fs::File;
    use std::io::prelude::*;

    #[test]
    fn test_hex2base64() {
        assert_eq!(
            hex2base64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d").unwrap(),
            "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
        );
    }

    #[test]
    fn test_xor() {
        assert_eq!(
            hex::encode(xor("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965").unwrap()),
            "746865206b696420646f6e277420706c6179"
        )
    }

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

    #[test]
    fn test_decrypt_aes_ecb_128() {
        let mut f = File::open("./data/7.txt").expect("file not found");

        let mut content = String::new();
        f.read_to_string(&mut content).expect("something went wrong reading the file");

        let result = decrypt_aes_ecb_128(&base64::decode(&str::replace(&content, "\n", "")).unwrap(), "YELLOW SUBMARINE".as_bytes()).unwrap();
        println!("{}", String::from_utf8(result).unwrap());
    }

    #[test]
    fn test_decrypt_aes_cbc_128() {
        let mut f = File::open("./data/10.txt").expect("file not found");

        let mut content = String::new();
        f.read_to_string(&mut content).expect("something went wrong reading the file");

        let result = decrypt_aes_cbc_128(&base64::decode(&str::replace(&content, "\n", "")).unwrap(), "YELLOW SUBMARINE".as_bytes(), &[b'\x00'; 16]).unwrap();
        println!("{}", String::from_utf8(result).unwrap());
    }

    #[test]
    fn test_encrypt_aes_cbc_128() {
        let mut f = File::open("./data/10.txt").expect("file not found");

        let mut content = String::new();
        f.read_to_string(&mut content).expect("something went wrong reading the file");

        let original = base64::decode(&str::replace(&content, "\n", "")).unwrap();
        let result = encrypt_aes_cbc_128(
            &decrypt_aes_cbc_128(&original, "YELLOW SUBMARINE".as_bytes(), &[b'\x00'; 16]).unwrap(),
            "YELLOW SUBMARINE".as_bytes(), &[b'\x00'; 16]
        ).unwrap();
        assert_eq!(result, original);
    }

    #[test]
    fn test_encrypt_aes_ecb_128() {
        let mut f = File::open("./data/7.txt").expect("file not found");

        let mut content = String::new();
        f.read_to_string(&mut content).expect("something went wrong reading the file");

        let original = base64::decode(&str::replace(&content, "\n", "")).unwrap();
        let result = encrypt_aes_ecb_128(
            &decrypt_aes_ecb_128(&original, "YELLOW SUBMARINE".as_bytes()).unwrap(),
            "YELLOW SUBMARINE".as_bytes()
        ).unwrap();
        assert_eq!(result, original);
    }

    #[test]
    fn test_detect_aes_ecb_128() {
        let mut f = File::open("./data/8.txt").expect("file not found");

        let mut content = String::new();
        f.read_to_string(&mut content).expect("something went wrong reading the file");

        let result = detect_aes_ecb_128(&content).unwrap();
        println!("{}", result);
    }

    #[test]
    fn test_pkcs7() {
        let padded = pkcs7("YELLOW SUBMARINE".as_bytes(), 20);
        assert_eq!(padded, "YELLOW SUBMARINE\x04\x04\x04\x04".as_bytes());
    }
}
