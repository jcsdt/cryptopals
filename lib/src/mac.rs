extern crate sha1;

use self::sha1::{Sha1, Digest};

pub fn secret_prefix_mac_sha1(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut input = vec![];
    input.extend_from_slice(key);
    input.extend_from_slice(message);
    Sha1::digest(&input).to_vec()
}

pub fn padded_message(message: &[u8], key_length: u32) -> Vec<u8> {
    let mut result = vec![];
    result.extend_from_slice(message);

    let mut length = key_length as usize + message.len();
    let mut pad_length = 64 - (length % 64); 

    result.push(0x80);
    pad_length -= 1;

    if pad_length < 8 {
        result.extend_from_slice(&vec![0u8; pad_length + 64]);
    } else {
        result.extend_from_slice(&vec![0u8; pad_length]);
    }

    let size = result.len();
    length = length << 3;
    for i in 0..8 {
        result[size - 1 - i] = ((length >> (i * 8)) & 0xFF) as u8;
    }
    
    result
}

pub fn break_sha1_length_extension(prefix_mac: &[u8], suffix: &[u8], original_length: usize) -> Vec<u8> {
    let mut state = [0u32; 5];
    for i in 0..5 {
        let mut n: u32 = prefix_mac[i * 4 + 3] as u32;
        n += (prefix_mac[i * 4 + 2] as u32) << (8 * 1);
        n += (prefix_mac[i * 4 + 1] as u32) << (8 * 2);
        n += (prefix_mac[i * 4] as u32) << (8 * 3);
        state[i] = n;
    }

    let mut sha1 = Sha1::with_state(state, (original_length + (64 - original_length % 64)) as u64);
    sha1.input(suffix);
    sha1.result().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    use common::gen_rand_bytes;

    #[test]
    fn test_secret_prefix_mac_sha1() {
        let key = gen_rand_bytes(16).unwrap();
        let another_key = gen_rand_bytes(16).unwrap();
        let message = gen_rand_bytes(52).unwrap();
        let mac = secret_prefix_mac_sha1(&key, &message);

        assert_ne!(mac, secret_prefix_mac_sha1(&another_key, &message));
    } 

    #[test]
    fn test_break_sha1_length_extension() {
        let key = gen_rand_bytes(16).unwrap();
        let message = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon";
        let suffix = ";admin=true";
        let mut forged_message = padded_message(&message.as_bytes(), 16);
        forged_message.extend_from_slice(&suffix.as_bytes());
        let mac = secret_prefix_mac_sha1(&key, &message.as_bytes());
        let forged_mac = secret_prefix_mac_sha1(&key, &forged_message);
        let broken_mac = break_sha1_length_extension(&mac, &suffix.as_bytes(), 16 + message.len());

        assert_eq!(broken_mac, forged_mac);
    }
}
