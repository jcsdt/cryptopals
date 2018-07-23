use base64;
use hex;
use rand;
use rand::prelude::*;

pub fn hex2base64(input: &str) -> Result<String, hex::FromHexError> {
    let b = hex::decode(input);
    b.map(|r| base64::encode(&r))
}

pub fn xor_bytes(l: &[u8], r: &[u8]) -> Vec<u8> {
    l.iter().zip(r.iter()).map(|(x, y)| x ^ y).collect()
}

pub fn xor(a: &str, b: &str) -> Result<Vec<u8>, hex::FromHexError> {
    let l = try!(hex::decode(a));
    let r = try!(hex::decode(b));
    Ok(xor_bytes(&l, &r))
}

pub fn gen_rand_bytes(size: usize) -> Result<Vec<u8>, rand::Error> {
    let mut result = vec![0; size];   
    try!(thread_rng().try_fill(&mut result[..]));
    Ok(result)
}

#[cfg(test)]
mod tests {

    use super::*;

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

}
