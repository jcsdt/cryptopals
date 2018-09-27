extern crate num_bigint;
extern crate num_traits;

use self::num_bigint::BigUint;
use sha2::{Sha256, Digest};

use aes::blockmode::decrypt_aes_cbc_128;
use aes::oracles::EncryptionOracleError;
use dh::{Dh, DhPlayer};
use padding;

pub trait EchoBot {
    fn get_params(&self) -> (BigUint, BigUint, BigUint);
}

impl DhPlayer {
    pub fn get_msg_from<T: Dh + EchoBot>(&mut self, other: &mut T) -> Result<Vec<u8>, EncryptionOracleError> {
        let (p, g, pubkey) = other.get_params();
        self.p = p;
        self.g = g;
        self.generate_pubkey();
        other.generate_session_key(&self.pubkey);
        self.generate_session_key(&pubkey);
        let m = other.send_encrypted_message()?;
        let plaintext = decrypt_aes_cbc_128(&m[16..], &self.get_session_key()[0..16], &m[0..16])?;
        Ok(padding::remove_pkcs7(&plaintext).unwrap())
    }
}

impl EchoBot for DhPlayer {
    fn get_params(&self) -> (BigUint, BigUint, BigUint) {
        (self.p.clone(), self.g.clone(), self.pubkey.clone())
    }
}

pub struct ParamInjectionAttacker<'a> {
   player: &'a mut DhPlayer,
   s: Vec<u8>
}

impl<'a> ParamInjectionAttacker<'a> {
    pub fn new(player: &'a mut DhPlayer) -> ParamInjectionAttacker {
        ParamInjectionAttacker {
            player,
            s: vec![],
        }
    }

    pub fn intercept_msg(&self) -> Result<Vec<u8>, EncryptionOracleError> {
        let m = self.player.send_encrypted_message()?;
        let plaintext = decrypt_aes_cbc_128(&m[16..], &self.s[0..16], &m[0..16])?;
        Ok(padding::remove_pkcs7(&plaintext).unwrap())
    }
}

impl<'a> Dh for ParamInjectionAttacker<'a> {
    fn generate_session_key(&mut self, _other_pubkey: &BigUint) {
        let (p, _g, _pubkey) = self.player.get_params();
        self.player.generate_session_key(&p);
        self.s = Sha256::digest(&[0]).to_vec();
    }

    fn send_encrypted_message(&self) -> Result<Vec<u8>, EncryptionOracleError> {
        self.player.send_encrypted_message()
    }
}

impl<'a> EchoBot for ParamInjectionAttacker<'a> {
    fn get_params(&self) -> (BigUint, BigUint, BigUint) {
        let (p, g, _pubkey) = self.player.get_params();
        (p.clone(), g, p)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_echo_bot() {
        let mut alice = DhPlayer::new_with_message("PING");
        let mut bob = DhPlayer::new_with_message("PONG");

        assert_eq!(bob.get_msg_from(&mut alice).unwrap(), b"PING");
    }

    #[test]
    fn test_mitm_echo_bot() {
        let mut alice = DhPlayer::new_with_message("PING");
        let mut bob = DhPlayer::new_with_message("PONG");

        let mut eve = ParamInjectionAttacker::new(&mut alice);

        assert_eq!(bob.get_msg_from(&mut eve).unwrap(), b"PING");
        assert_eq!(eve.intercept_msg().unwrap(), b"PING");
    }
}
