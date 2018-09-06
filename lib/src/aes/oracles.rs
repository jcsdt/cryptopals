use std;

use crypto;
use rand;

use aes;
use super::super::common;
use super::super::padding;

use rand::prelude::*;

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

pub trait Encrypt {
    fn encrypt(&self, input: &[u8]) -> Result<Vec<u8>, crypto::symmetriccipher::SymmetricCipherError>;
}

pub trait Decrypt {
    fn decrypt(&self, input: &[u8]) -> Result<Vec<u8>, crypto::symmetriccipher::SymmetricCipherError>;
}

#[derive(Debug, PartialEq)]
pub enum CipherMode {
    ECB,
    CBC,
}

pub struct OracleEcbOrCbc {}

impl OracleEcbOrCbc {
    pub fn encrypt(input: &[u8]) -> Result<(Vec<u8>, CipherMode), EncryptionOracleError> {
        let key = try!(common::gen_rand_bytes(16));
        let mut plaintext = vec![];
    
        plaintext.append(&mut try!(common::gen_rand_bytes(thread_rng().gen_range(5, 10))));
        plaintext.extend_from_slice(input);
        plaintext.append(&mut try!(common::gen_rand_bytes(thread_rng().gen_range(5, 10))));
        
        plaintext = padding::pkcs7(&plaintext, (plaintext.len() / 16 + 1) * 16); 
    
        let cipher_text = if rand::random() {
            (try!(aes::blockmode::encrypt_aes_ecb_128(&plaintext, &key)), CipherMode::ECB)
        } else {
            let iv = try!(common::gen_rand_bytes(16));
            (try!(aes::blockmode::encrypt_aes_cbc_128(&plaintext, &key, &iv)), CipherMode::CBC)
        };
    
        Ok(cipher_text)
    }
}

pub struct OracleEcb {
    key: Vec<u8>,
    plaintext: Vec<u8>
}

impl OracleEcb {
    pub fn new(plaintext: Vec<u8>) -> Result<Self, rand::Error> {
        let key = try!(common::gen_rand_bytes(16));
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
        let padded = padding::pkcs7(&to_encrypt, (to_encrypt.len() / 16 + 1) * 16);
        aes::blockmode::encrypt_aes_ecb_128(&padded, &self.key)
    }
}

pub struct OracleEcbWithPrefix {
    key: Vec<u8>,
    plaintext: Vec<u8>,
    prefix: Vec<u8>
}

impl OracleEcbWithPrefix {
    pub fn new(plaintext: Vec<u8>) -> Result<Self, rand::Error> {
        let key = try!(common::gen_rand_bytes(16));
        let prefix = common::gen_rand_bytes(thread_rng().gen_range(0, 48)).unwrap();
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
        let padded = padding::pkcs7(&to_encrypt, (to_encrypt.len() / 16 + 1) * 16);
        aes::blockmode::encrypt_aes_ecb_128(&padded, &self.key)
    }
}

pub struct OracleCbc {
    pub key: Vec<u8>,
    iv: Vec<u8>,
}

impl OracleCbc {
    pub fn new() -> Result<OracleCbc, rand::Error> {
        let key = common::gen_rand_bytes(16)?;
        let iv = common::gen_rand_bytes(16)?;
        Ok(OracleCbc {
            key,
            iv,
        })
    }

    pub fn new_without_iv() -> Result<OracleCbc, rand::Error> {
        let key = common::gen_rand_bytes(16)?;
        Ok(OracleCbc {
            key: key.clone(),
            iv: key,
        })
    }
}

impl Encrypt for OracleCbc {
    fn encrypt(&self, input: &[u8]) -> Result<Vec<u8>, crypto::symmetriccipher::SymmetricCipherError> {
        let mut bytes = vec![];
        bytes.extend_from_slice("comment1=cooking%20MCs;userdata=".as_bytes());
        bytes.extend_from_slice(input);
        bytes.extend_from_slice(";comment2=%20like%20a%20pound%20of%20bacon".as_bytes());

        bytes = padding::pkcs7(&bytes, (bytes.len() / 16 + 1) * 16);
        let result = aes::blockmode::encrypt_aes_cbc_128(&bytes, &self.key, &self.iv)?;
        Ok(result)
    }
}

impl Decrypt for OracleCbc {
    fn decrypt(&self, input: &[u8]) -> Result<Vec<u8>, crypto::symmetriccipher::SymmetricCipherError> {
        let mut result = aes::blockmode::decrypt_aes_cbc_128(input, &self.key, &self.iv)?;
        result = padding::remove_pkcs7(&result).unwrap();
        Ok(result)
    }
}

pub struct OracleCtr {
    key: Vec<u8>,
    nonce: u64,
}

impl OracleCtr {
    pub fn new() -> Result<OracleCtr, rand::Error> {
        let key = common::gen_rand_bytes(16)?;
        let nonce = rand::random::<u64>();
        Ok(OracleCtr {
            key,
            nonce,
        })
    }
}

impl Encrypt for OracleCtr {
    fn encrypt(&self, input: &[u8]) -> Result<Vec<u8>, crypto::symmetriccipher::SymmetricCipherError> {
        let mut bytes = vec![];
        bytes.extend_from_slice("comment1=cooking%20MCs;userdata=".as_bytes());
        bytes.extend_from_slice(input);
        bytes.extend_from_slice(";comment2=%20like%20a%20pound%20of%20bacon".as_bytes());

        let result = aes::streammode::ctr_128(&bytes, &self.key, self.nonce)?;
        Ok(result)
    }
}

impl Decrypt for OracleCtr {
    fn decrypt(&self, input: &[u8]) -> Result<Vec<u8>, crypto::symmetriccipher::SymmetricCipherError> {
        let result = aes::streammode::ctr_128(input, &self.key, self.nonce)?;
        Ok(result)
    }
}

pub struct User {
    email: String,
    uid: u32,
    role: String,
}

impl User {
    pub fn profile_for(email: &str) -> User {
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

    pub fn role(&self) -> &str {
        &self.role
    }
}

pub struct OracleEcbUser {
    key: Vec<u8>,
}

impl OracleEcbUser {
    pub fn new() -> Result<Self, rand::Error> {
        let key = try!(common::gen_rand_bytes(16));
        Ok(OracleEcbUser {
            key,
        })
    }

    pub fn encrypt(&self, user: &User) -> Result<Vec<u8>, crypto::symmetriccipher::SymmetricCipherError> {
        let mut to_encrypt = vec![];
        to_encrypt.extend_from_slice(user.encode().as_bytes());
        let padded = padding::pkcs7(&to_encrypt, (to_encrypt.len() / 16 + 1) * 16);
        aes::blockmode::encrypt_aes_ecb_128(&padded, &self.key)
    }

    pub fn decrypt(&self, input: &[u8]) -> Result<User, crypto::symmetriccipher::SymmetricCipherError> {
        let v = aes::blockmode::decrypt_aes_ecb_128(input, &self.key)?;
        let unpadded = padding::remove_pkcs7(&v).unwrap();
        Ok(User::decode(&String::from_utf8(unpadded).unwrap()))
    }
}

pub struct PaddingOracle {
    key: Vec<u8>,
}

impl PaddingOracle {
    pub fn new() -> Result<Self, rand::Error> {
        let key = common::gen_rand_bytes(16)?;
        Ok(PaddingOracle {
            key,
        })
    }

    pub fn check_padding(&self, input: &[u8]) -> Result<bool, crypto::symmetriccipher::SymmetricCipherError> {
        let result = aes::blockmode::decrypt_aes_cbc_128(&input[16..], &self.key, &input[..16])?;
        Ok(padding::remove_pkcs7(&result).is_ok())
    }
}

impl Encrypt for PaddingOracle {
    fn encrypt(&self, input: &[u8]) -> Result<Vec<u8>, crypto::symmetriccipher::SymmetricCipherError> {
        let mut iv = common::gen_rand_bytes(16).unwrap();
        let padded = padding::pkcs7(input, (input.len() / 16 + 1) * 16);
        let result  = aes::blockmode::encrypt_aes_cbc_128(&padded, &self.key, &iv)?;
        iv.extend_from_slice(&result);
        Ok(iv)
    }
}

pub struct OracleEditCtr {
    key: Vec<u8>,
    nonce: u64,
}

impl OracleEditCtr {
    pub fn new() -> Result<OracleEditCtr, rand::Error> {
        let key = common::gen_rand_bytes(16)?;
        let nonce = rand::random::<u64>();
        Ok(OracleEditCtr {
            key,
            nonce,
        })
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, crypto::symmetriccipher::SymmetricCipherError> {
       aes::streammode::ctr_128(plaintext, &self.key, self.nonce)
    }

    pub fn edit(&self, cipher: &[u8], offset: u32, new_text: &[u8]) -> Result<Vec<u8>, crypto::symmetriccipher::SymmetricCipherError> {
        let block_number = offset / 16;

        let tail = &cipher[(block_number * 16) as usize..];

        let mut keystream = vec![];
        keystream.extend_from_slice(&self.nonce.to_bytes());
        keystream.extend_from_slice(&(block_number as u64).to_bytes());
        let block = aes::blockmode::encrypt_aes_ecb_128(&keystream, &self.key)?;
        let decrypted = common::xor_bytes(&block[..std::cmp::min(tail.len(), 16)], &tail[0..std::cmp::min(tail.len(), 16)]);

        let mut new_tail = vec![];
        new_tail.extend_from_slice(&decrypted[..(offset % 16) as usize]);
        new_tail.extend_from_slice(new_text);

        let (oks, errors): (Vec<_>, Vec<_>) = new_tail.chunks(16).enumerate().map(|(i, c)| {
            let mut keystream = vec![];
            keystream.extend_from_slice(&self.nonce.to_bytes());
            keystream.extend_from_slice(&((i + block_number as usize) as u64).to_bytes());
            let block = aes::blockmode::encrypt_aes_ecb_128(&keystream, &self.key);
            block.map(|b| common::xor_bytes(&b[..c.len()], c))
        }).partition(Result::is_ok);

        if !errors.is_empty() {
            return Err(errors.into_iter().map(Result::unwrap_err).nth(0).unwrap());
        }
        
        let mut result = vec![];
        result.extend_from_slice(&cipher[..(block_number * 16) as usize]);
        result.append(&mut oks.into_iter().map(Result::unwrap).flatten().collect());

        Ok(result)
    }
}
