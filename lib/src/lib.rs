#![feature(iterator_flatten)]
use std::f32;
use std::collections::HashMap;

extern crate base64;
extern crate hex;
extern crate crypto;
extern crate rand;

use rand::prelude::*;

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

fn count_repeating_blocks(input: &[u8]) -> u32  { 
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
        let score = count_repeating_blocks(&try!(hex::decode(s)));
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

pub fn gen_rand_bytes(size: usize) -> Result<Vec<u8>, rand::Error> {
    let mut result = vec![0; size];   
    try!(thread_rng().try_fill(&mut result[..]));
    Ok(result)
}

#[derive(Debug)]
pub enum EncryptionOracleError {
    RandomError(rand::Error),
    CipherError(crypto::symmetriccipher::SymmetricCipherError),
}

impl From<rand::Error> for EncryptionOracleError {
    fn from(err: rand::Error) -> EncryptionOracleError {
        EncryptionOracleError::RandomError(err)
    }
}

impl From<crypto::symmetriccipher::SymmetricCipherError> for EncryptionOracleError {
    fn from(err: crypto::symmetriccipher::SymmetricCipherError) -> EncryptionOracleError {
        EncryptionOracleError::CipherError(err)
    }
}

#[derive(Debug, PartialEq)]
pub enum CipherMode {
    ECB,
    CBC,
}

pub fn encryption_oracle_ecb_cbc(input: &[u8]) -> Result<(Vec<u8>, CipherMode), EncryptionOracleError> {
    let key = try!(gen_rand_bytes(16));
    let mut plaintext = vec![];

    plaintext.append(&mut try!(gen_rand_bytes(thread_rng().gen_range(5, 10))));
    plaintext.extend_from_slice(input);
    plaintext.append(&mut try!(gen_rand_bytes(thread_rng().gen_range(5, 10))));
    
    plaintext = pkcs7(&plaintext, (plaintext.len() / 16 + 1) * 16); 

    let cipher_text = if rand::random() {
        (try!(encrypt_aes_ecb_128(&plaintext, &key)), CipherMode::ECB)
    } else {
        let iv = try!(gen_rand_bytes(16));
        (try!(encrypt_aes_cbc_128(&plaintext, &key, &iv)), CipherMode::CBC)
    };

    Ok(cipher_text)
}

pub fn detection_oracle_ecb_cbc(input: &[u8]) -> CipherMode {
    let c = count_repeating_blocks(input);
    if c > 1 {CipherMode::ECB} else {CipherMode::CBC}
}

pub struct OracleEcb {
    key: Vec<u8>,
    plaintext: Vec<u8>
}

pub struct OracleEcbWithPrefix {
    key: Vec<u8>,
    plaintext: Vec<u8>,
    prefix: Vec<u8>
}

pub trait Encrypt {
    fn encrypt(&self, input: &[u8]) -> Result<Vec<u8>, crypto::symmetriccipher::SymmetricCipherError>;
}

impl OracleEcb {
    fn new(plaintext: Vec<u8>) -> Result<Self, rand::Error> {
        let key = try!(gen_rand_bytes(16));
        Ok(OracleEcb {
            key,
            plaintext,
        })
    }
}

impl Encrypt for OracleEcb {
    fn encrypt(&self, input: &[u8]) -> Result<Vec<u8>, crypto::symmetriccipher::SymmetricCipherError> {
        let mut to_encrypt = vec![];
        to_encrypt.extend_from_slice(input);
        to_encrypt.extend_from_slice(&self.plaintext);
        let padded = pkcs7(&to_encrypt, (to_encrypt.len() / 16 + 1) * 16);
        encrypt_aes_ecb_128(&padded, &self.key)
    }
}

impl OracleEcbWithPrefix {
    fn new(plaintext: Vec<u8>) -> Result<Self, rand::Error> {
        let key = try!(gen_rand_bytes(16));
        let prefix = gen_rand_bytes(thread_rng().gen_range(0, 48)).unwrap();
        Ok(OracleEcbWithPrefix {
            key,
            plaintext,
            prefix,
        })
    }
}

impl Encrypt for OracleEcbWithPrefix {
    fn encrypt(&self, input: &[u8]) -> Result<Vec<u8>, crypto::symmetriccipher::SymmetricCipherError> {
        let mut to_encrypt = vec![];
        to_encrypt.extend_from_slice(&self.prefix);
        to_encrypt.extend_from_slice(input);
        to_encrypt.extend_from_slice(&self.plaintext);
        let padded = pkcs7(&to_encrypt, (to_encrypt.len() / 16 + 1) * 16);
        encrypt_aes_ecb_128(&padded, &self.key)
    }
}

fn find_block_size<T: Encrypt>(oracle: &T) -> usize {
    let mut size = 1;
    let original_len = oracle.encrypt(&[]).unwrap().len();
    loop {
        let pre = vec![b'A'; size];
        let text = oracle.encrypt(&pre).unwrap();
        if text.len() == original_len {
            size += 1;
            continue;
        } else {
            return text.len() - original_len;
        }
    }
}

fn is_oracle_ecb<T: Encrypt>(block_size: usize, oracle: &T) -> bool {
    let text = oracle.encrypt(&vec![b'A'; block_size * 3]).unwrap();
    count_repeating_blocks(&text) > 1
}

fn remove_pkcs7(input: &[u8]) -> Vec<u8> {
    let last_byte = input[input.len() - 1];
    if input[input.len() - last_byte as usize..].iter().filter(|&b| *b != last_byte).collect::<Vec<&u8>>().is_empty() {
        return input[..input.len() - last_byte as usize].to_vec();
    }

    input.to_vec()
}

pub fn crack_aes_ecb_128_with_prefix<T: Encrypt>(oracle: &T) -> Result<Vec<u8>, crypto::symmetriccipher::SymmetricCipherError> {
    let mut attack = vec![];
    let mut skip = 0;
    for i in 0..16 {
        let mut padding = vec![];
        padding.extend_from_slice(&attack);
        padding.extend_from_slice(&[b'A'; 16 * 2]);

        let ciphered = oracle.encrypt(&padding)?;
        let s = ciphered[..].chunks(16).zip(ciphered[..].chunks(16).skip(1))
            .enumerate()
            .filter(|(_, (a, b))| a == b)
            .map(|(idx, _)| idx).nth(0);

        match s {
            Some(v) => {
                skip = v;
                break;
            },
            None => {}
        }

        attack.push(i as u8);
    };

    crack_aes_ecb_128(oracle, &attack, skip)
}

pub fn crack_aes_ecb_128<T: Encrypt>(oracle: &T, prefix: &[u8], skip: usize) -> Result<Vec<u8>, crypto::symmetriccipher::SymmetricCipherError> {
    let block_size = find_block_size(oracle);
    assert_eq!(16, block_size, "block size known to be 16");
    let is_ecb = is_oracle_ecb(block_size, oracle);
    if !is_ecb {
        panic!("Encryption oracle should use ECB to be cracked");
    }

    let mut attack_padding = vec![];
    attack_padding.extend_from_slice(prefix);
    attack_padding.extend_from_slice(&vec![b'A'; block_size - 1]);

    let mut blocks_to_crack : std::collections::BTreeMap<usize, Vec<u8>> = std::collections::BTreeMap::new();
    for s in 0..block_size {
        let cipher = oracle.encrypt(&attack_padding[..prefix.len() + block_size - 1 - s])?;
        for (i, c) in cipher[..].chunks(block_size).skip(skip).enumerate() {
            blocks_to_crack.insert(i * (block_size ) + s, c.to_vec());
        }

        for (&k, ref to_decode) in blocks_to_crack.range(attack_padding[prefix.len() + block_size - 1..].len()..) {
            // decoded.len() is changed within this loop, 
            // that why the condition makes sense
            if k > attack_padding[prefix.len() + block_size - 1..].len() {
                break;
            }

            for n in 0..256 {
                let b = n as u8;
                let mut padding = vec![];
                padding.extend_from_slice(&prefix);
                padding.extend_from_slice(&attack_padding[attack_padding.len() - (block_size - 1)..]);
                padding.push(b);
                let cipher = oracle.encrypt(&padding)?;
                if &cipher[..].chunks(block_size).skip(skip).nth(0).unwrap().to_vec() == *to_decode {
                    attack_padding.push(b);
                    break;
                }
            }
        }
    }

    Ok(remove_pkcs7(&attack_padding[prefix.len() + block_size - 1..]))
}

pub struct User {
    email: String,
    uid: u32,
    role: String,
}

impl User {
    fn profile_for(email: &str) -> User {
        User {
            email: str::replace(&str::replace(email, "&", ""), "=", "").to_string(),
            uid: 10,
            role: "user".to_string()
        }
    }

    fn encode(&self) -> String {
        format!("email={}&uid={}&role={}", &self.email, self.uid, &self.role)
    }

    fn decode(input: &str) -> User {
        let map: std::collections::HashMap<&str, &str> = input.split("&").map(|s| {
            let idx = s.find("=");
            let (key, value) = s.split_at(idx.unwrap());
            // remove = sign
            (key, &value[1..])
        }).collect();

        User {
            email: map["email"].to_string(),
            uid: map["uid"].parse::<u32>().unwrap(),
            role: map["role"].to_string(),
        }
    }
}

pub struct OracleEcbUser {
    key: Vec<u8>,
}

impl OracleEcbUser {
    fn new() -> Result<Self, rand::Error> {
        let key = try!(gen_rand_bytes(16));
        Ok(OracleEcbUser {
            key,
        })
    }

    fn encrypt(&self, user: &User) -> Result<Vec<u8>, crypto::symmetriccipher::SymmetricCipherError> {
        let mut to_encrypt = vec![];
        to_encrypt.extend_from_slice(user.encode().as_bytes());
        let padded = pkcs7(&to_encrypt, (to_encrypt.len() / 16 + 1) * 16);
        encrypt_aes_ecb_128(&padded, &self.key)
    }

    fn decrypt(&self, input: &[u8]) -> Result<User, crypto::symmetriccipher::SymmetricCipherError> {
        let v = decrypt_aes_ecb_128(input, &self.key)?;
        let unpadded = remove_pkcs7(&v);
        Ok(User::decode(&String::from_utf8(unpadded).unwrap()))
    }
}

pub fn spoof_admin_user_ecb(oracle: OracleEcbUser) -> Result<User, crypto::symmetriccipher::SymmetricCipherError> {
    let mut email = vec![];
    email.extend_from_slice("AAAAAAAAAAadmin".as_bytes());
    email.extend_from_slice(&[b'\x0b'; 11]);
    let user = User::profile_for(&String::from_utf8(email).unwrap());
    let cipher = oracle.encrypt(&user).unwrap();
    let admin_block = &cipher[16..32];
    let user = User::profile_for("quatorze@me.f");
    let cipher = oracle.encrypt(&user).unwrap();
    
    let mut cut_and_paste = vec![];
    cut_and_paste.extend_from_slice(&cipher[..32]);
    cut_and_paste.extend_from_slice(admin_block);
    oracle.decrypt(&cut_and_paste)
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

    #[test]
    fn test_detection_oracle_ecb_cbc() {
        let input = [b'A'; 16 * 3];
        let (cipher, mode) = encryption_oracle_ecb_cbc(&input[..]).unwrap();
        let detected_mode = detection_oracle_ecb_cbc(&cipher);
        assert_eq!(detected_mode, mode);
    }

    #[test]
    fn test_crack_ecb_simple() {
        let plaintext = base64::decode("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK").unwrap();
        let oracle = OracleEcb::new(plaintext.clone()).unwrap();
        let recovered_text = crack_aes_ecb_128(&oracle, &[], 0).unwrap();
        assert_eq!(plaintext, recovered_text);
        println!("{}", String::from_utf8(recovered_text).unwrap());
    }

    #[test]
    fn test_spoof_admin_user_ecb() {
        let oracle = OracleEcbUser::new().unwrap();
        let user = spoof_admin_user_ecb(oracle).unwrap();
        assert_eq!(user.role, "admin");
    }

    #[test]
    fn test_crack_ecb_with_prefix() {
        let plaintext = base64::decode("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK").unwrap();
        let oracle = OracleEcbWithPrefix::new(plaintext.clone()).unwrap();
        let recovered_text = crack_aes_ecb_128_with_prefix(&oracle).unwrap();
        assert_eq!(plaintext, recovered_text);
        println!("{}", String::from_utf8(recovered_text).unwrap());
    }
}
