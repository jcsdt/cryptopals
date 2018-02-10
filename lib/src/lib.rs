extern crate base64;
extern crate hex;

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

pub fn crack_single_xor(input: &str) -> Result<String, hex::FromHexError> {
   let mut max_score = 0;
   let mut candidate_string = String::new();

   let len_input = input.len();
   let decoded = try!(hex::decode(input));
   // Test all ASCII values
   for k in 0u8..128 {
        let key = std::iter::repeat(k).take(len_input).collect::<Vec<u8>>();

        let xored = xor_bytes(&decoded, &key);
        let xored_str = String::from_utf8(xored);
        let score = match  xored_str {
            Ok(ref r) => score_eng(&r),
            Err(_) => 0,
        };

        if score > max_score {
            max_score = score;
            // Can't panic here since score > 0
            candidate_string = xored_str.unwrap().clone();
        }
   }

   return Ok(candidate_string);
}

fn score_eng(input: &str) -> usize {
    let mut score = 0;
    let most_common_letters = "ETAOIN SHRDLU";
    let number_of_letters = most_common_letters.len();
    for c in input.to_uppercase().chars() {
        for (idx, r) in most_common_letters.char_indices() {
            if r == c {
                score += number_of_letters - idx;
            }
        }
    }

    score
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

    #[test]
    fn test_crack_single_xor() {
        println!("{}", crack_single_xor("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736").unwrap())
    }
}
