use std;
use std::collections::HashMap;

use crypto;
use hex;

use aes::oracles::*;
use common::xor_bytes;
use padding::remove_pkcs7;
use super::super::padding;

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

pub fn detection_oracle_ecb_cbc(input: &[u8]) -> CipherMode {
    let c = count_repeating_blocks(input);
    if c > 1 {CipherMode::ECB} else {CipherMode::CBC}
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

    Ok(padding::remove_pkcs7(&attack_padding[prefix.len() + block_size - 1..]).unwrap())
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

pub fn spoof_admin_user_cbc<T: Encrypt + Decrypt>(oracle: T) -> bool {
    let mut cipher = oracle.encrypt(":admin<true:userdata=helloworld!!".as_bytes()).unwrap();

    cipher[16] = cipher[16] ^ 1;
    cipher[22] = cipher[22] ^ 1;
    cipher[27] = cipher[27] ^ 1;
    
    let decoded = oracle.decrypt(&cipher).unwrap();
    let result = String::from_utf8_lossy(&decoded);
    result.contains(";admin=true;")
}

pub fn spoof_admin_user_ctr<T: Encrypt + Decrypt>(oracle: T) -> bool {
    let mut cipher = oracle.encrypt(":admin<true:userdata=helloworld!!".as_bytes()).unwrap();

    cipher[32] = cipher[32] ^ 1;
    cipher[38] = cipher[38] ^ 1;
    cipher[43] = cipher[43] ^ 1;
    
    let decoded = oracle.decrypt(&cipher).unwrap();
    let result = String::from_utf8_lossy(&decoded);
    result.contains(";admin=true;")
}

fn crack_inter_padding_oracle(chunk: &[u8], oracle: &PaddingOracle) -> Result<Vec<u8>, crypto::symmetriccipher::SymmetricCipherError> {
    let mut payload = vec![0; 16];
    payload.extend_from_slice(chunk);

    let mut inter = vec![0; 16];

    for i in 0..16 {
        loop {
            if oracle.check_padding(&payload)? {
                inter[16 - (i + 1)] = (i + 1) as u8 ^ payload[16 - (i + 1)];
                (0..(i + 1)).for_each(|j| payload[16 - (j + 1)] = (i + 2) as u8 ^ inter[16 - (j + 1)]);
                break;
            } else {
                payload[16 - (i + 1)] += 1;
            }
        }
    }

    Ok(inter)
}

pub fn crack_padding_oracle(cipher: &[u8], oracle: PaddingOracle) -> Result<Vec<u8>, crypto::symmetriccipher::SymmetricCipherError> {
    let inter = cipher.chunks(16).skip(1)
        .map(|c| crack_inter_padding_oracle(c, &oracle))
        .try_fold(vec![], |mut acc, r| {
            if r.is_err() {
                r
            } else {
                acc.extend_from_slice(&r.unwrap());
                Ok(acc)
            }
        })?;

    Ok(remove_pkcs7(&xor_bytes(&inter, cipher)).unwrap())
}

pub fn crack_random_access_ctr(cipher: &[u8], oracle: &OracleEditCtr) -> Result<Vec<u8>, crypto::symmetriccipher::SymmetricCipherError> {
    let (oks, errors): (Vec<_>, Vec<_>) = cipher.iter().enumerate().rev().map(|(i, &b)| {
        for n in 0..256u32 {
            if oracle.edit(cipher, i as u32, &[n as u8])?[i] == b {
                return Ok(n as u8);
            }
        }

        Ok(0)
    }).partition(Result::is_ok);

    if !errors.is_empty() {
        return Err(errors.into_iter().map(Result::unwrap_err).nth(0).unwrap());
    }

    Ok(oks.into_iter().map(Result::unwrap).rev().collect::<Vec<u8>>())
}

pub fn recover_key_from_iv_key_cbc(oracle: &OracleCbc) -> Result<Vec<u8>, crypto::symmetriccipher::SymmetricCipherError> {
    let mut cipher = oracle.encrypt(&"yellowsubmarine!".bytes().collect::<Vec<u8>>())?;
    for b in &mut cipher[16..32] {
        *b = 0;
    }

    let mut forged_cipher = vec![];
    forged_cipher.extend_from_slice(&cipher[..32]);
    forged_cipher.extend_from_slice(&cipher[..16]);
    forged_cipher.extend_from_slice(&cipher[48..]);

    let plaintext = oracle.decrypt(&forged_cipher)?;
    println!("{:?}", plaintext);
    Ok(xor_bytes(&plaintext[..16], &plaintext[32..48]))
}

#[cfg(test)]
mod tests {

    use rand::Rng;

    use super::*;

    use std::fs::File;
    use std::io::prelude::*;

    #[test]
    fn test_detect_aes_ecb_128() {
        let mut f = File::open("./data/8.txt").expect("file not found");

        let mut content = String::new();
        f.read_to_string(&mut content).expect("something went wrong reading the file");

        let result = detect_aes_ecb_128(&content).unwrap();
        println!("{}", result);
    }

    #[test]
    fn test_detection_oracle_ecb_cbc() {
        let input = [b'A'; 16 * 3];
        let (cipher, mode) = OracleEcbOrCbc::encrypt(&input[..]).unwrap();
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
        assert_eq!(user.role(), "admin");
    }

    #[test]
    fn test_crack_ecb_with_prefix() {
        let plaintext = base64::decode("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK").unwrap();
        let oracle = OracleEcbWithPrefix::new(plaintext.clone()).unwrap();
        let recovered_text = crack_aes_ecb_128_with_prefix(&oracle).unwrap();
        assert_eq!(plaintext, recovered_text);
        println!("{}", String::from_utf8(recovered_text).unwrap());
    }

    #[test]
    fn test_spoof_admin_user_cbc() {
        let oracle = OracleCbc::new().unwrap();
        assert!(spoof_admin_user_cbc(oracle));
    }

    #[test]
    fn test_spoof_admin_user_ctr() {
        let oracle = OracleCtr::new().unwrap();
        assert!(spoof_admin_user_ctr(oracle));
    }

    #[test]
    fn test_crack_padding_oracle() {
        let texts = [
            "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
            "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
            "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
            "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
            "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
            "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
            "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
            "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
            "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
            "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
        ];
        let plaintext = base64::decode(texts[rand::thread_rng().gen_range(0, 10)]).unwrap();
        let oracle = PaddingOracle::new().unwrap();
        let cipher = oracle.encrypt(&plaintext).unwrap();
        let cracked = crack_padding_oracle(&cipher, oracle).unwrap();
        assert_eq!(cracked, plaintext);
        println!("{}", String::from_utf8(plaintext).unwrap());
    }

    #[test]
    fn test_crack_random_access_ctr() {
        let mut f = File::open("./data/25.txt").expect("file not found");

        let mut content = String::new();
        f.read_to_string(&mut content).expect("something went wrong reading the file");

        let plaintext = base64::decode(&str::replace(&content, "\n", "")).unwrap();

        let oracle = OracleEditCtr::new().unwrap();
        let cipher = oracle.encrypt(&plaintext).unwrap();

        let cracked = crack_random_access_ctr(&cipher, &oracle).unwrap();

        assert_eq!(cracked, plaintext);
    }

    #[test]
    fn test_recover_from_iv_key_cbc() {
        let oracle = OracleCbc::new_without_iv().unwrap();
        let recovered_key = recover_key_from_iv_key_cbc(&oracle).unwrap();
        assert_eq!(recovered_key, oracle.key);
    }
}
