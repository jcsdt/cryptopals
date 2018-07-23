use aes;
use crypto;

use common;

pub fn ctr_128(input: &[u8], key: &[u8], nonce: u64) -> Result<Vec<u8>, crypto::symmetriccipher::SymmetricCipherError> {
    let (oks, errors): (Vec<_>, Vec<_>) = input.chunks(16).enumerate().map(|(i, c)| {
        let mut keystream = vec![];
        keystream.extend_from_slice(&nonce.to_bytes());
        keystream.extend_from_slice(&(i as u64).to_bytes());
        let block = aes::blockmode::encrypt_aes_ecb_128(&keystream, &key);
        block.map(|b| common::xor_bytes(&b[..c.len()], c))
    }).partition(Result::is_ok);

    if !errors.is_empty() {
        return Err(errors.into_iter().map(Result::unwrap_err).nth(0).unwrap());
    }
    
    Ok(oks.into_iter().map(Result::unwrap).flatten().collect())
}

#[cfg(test)]
mod tests {
    
    use base64;

    use super::*;

    #[test]
    fn test_ctr_128() {
        let ciphertext = base64::decode("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==").unwrap();
        println!("{}", String::from_utf8(ctr_128(&ciphertext, "YELLOW SUBMARINE".as_bytes(), 0).unwrap()).unwrap());
    }
}
