extern crate sha1;

use self::sha1::{Sha1, Digest};

pub fn secret_prefix_mac_sha1(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut input = vec![];
    input.extend_from_slice(key);
    input.extend_from_slice(message);
    let mut result = vec![];
    result.extend_from_slice(&Sha1::digest(&input));
    result
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
}
