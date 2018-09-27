use rand;
use num_bigint::{ToBigUint, BigUint, RandBigInt};
use sha2::{Sha256, Digest};

use aes::blockmode::encrypt_aes_cbc_128;
use aes::oracles::EncryptionOracleError;
use common::{gen_rand_bytes, modexp};
use padding;

pub struct DhPlayer {
    pub p: BigUint,
    pub g: BigUint,
    pub pubkey: BigUint,
    random: BigUint,
    s: Vec<u8>,
    msg: String,
}

pub trait Dh {
    fn generate_session_key(&mut self, other_pubkey: &BigUint);
    fn send_encrypted_message(&self) -> Result<Vec<u8>, EncryptionOracleError>;
}

impl Dh for DhPlayer {
    fn generate_session_key(&mut self, other_pubkey: &BigUint) {
       self.s = Sha256::digest(&modexp(other_pubkey, &self.random, &self.p).to_bytes_be()).to_vec();
    }

    fn send_encrypted_message(&self) -> Result<Vec<u8>, EncryptionOracleError> {
        let mut result = vec![];
        let iv = gen_rand_bytes(16)?; 
        let plaintext = padding::pkcs7(&self.msg.as_bytes(), (self.msg.len() / 16 + 1) * 16); 
        let cipher = encrypt_aes_cbc_128(&plaintext, &self.s[0..16], &iv)?;
        result.extend_from_slice(&iv);
        result.extend_from_slice(&cipher);
        Ok(result)
    }
}

impl DhPlayer {
    pub fn new() -> DhPlayer {
        DhPlayer::new_with_message("")
    }

    pub fn new_with_message(msg: &str) -> DhPlayer {
        let p = BigUint::parse_bytes(b"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 16).unwrap();
        let g = 2u32.to_biguint().unwrap();
        let random = rand::thread_rng().gen_biguint_below(&p);
        let pubkey = modexp(&g, &random, &p);
        DhPlayer {
            p,
            g,
            pubkey,
            random,
            s: vec![],
            msg: String::from(msg),
        }
    }

    pub fn generate_pubkey(&mut self) {
        self.random = rand::thread_rng().gen_biguint_below(&self.p);
        self.pubkey = modexp(&self.g, &self.random, &self.p);
    }

    pub fn get_pubkey(&self) -> &BigUint {
        &self.pubkey
    }

    pub fn get_session_key(&self) -> &[u8] {
        &self.s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dh() {
        let mut alice = DhPlayer::new();
        let mut bob = DhPlayer::new();

        alice.generate_session_key(bob.get_pubkey());
        bob.generate_session_key(alice.get_pubkey());

        assert_eq!(alice.get_session_key(), bob.get_session_key());
    }
}
