use std;

use crypto;
use crypto::{ buffer };
use crypto::buffer::{ ReadBuffer, WriteBuffer, BufferResult };

use super::super::common;

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


pub fn encrypt_aes_cbc_128(input: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, crypto::symmetriccipher::SymmetricCipherError> {
    let mut result = Vec::<u8>::new();
    let mut to_xor = iv.to_vec();

    for c in input.chunks(16) {
        let mut ciphered = try!(encrypt_aes_ecb_128(&common::xor_bytes(c, to_xor.as_slice()), key));
        to_xor = ciphered.clone();
        result.append(&mut ciphered);
    }

    Ok(result)
}

pub fn decrypt_aes_cbc_128(input: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, crypto::symmetriccipher::SymmetricCipherError> {
    let iter = input.chunks(16).map(|c| decrypt_aes_ecb_128(c, key).unwrap());
    let result = iter.zip(std::iter::once(iv).chain(input.chunks(16))).map(|(a, b)| common::xor_bytes(a.as_slice(), b)).flatten().collect();
    Ok(result)
}

#[cfg(test)]
mod tests {

    use super::*;

    use std::fs::File;
    use std::io::prelude::*;

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


}
