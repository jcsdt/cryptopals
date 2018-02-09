extern crate base64;
extern crate hex;

pub fn hex2base64(input: &str) -> Result<String, hex::FromHexError> {
    let b = hex::decode(input);
    b.map(|r| base64::encode(&r))
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
}
