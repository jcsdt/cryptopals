extern crate num_bigint;
extern crate num_traits;

use self::num_bigint::BigUint;
use self::num_traits::{Zero, One};
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

pub trait ParamInjection<'p> {
    fn intercept_msg(&self) -> Result<Vec<u8>, EncryptionOracleError> {
        let m = self.get_attacker().get_player().send_encrypted_message()?;
        let plaintext = decrypt_aes_cbc_128(&m[16..], &self.get_attacker().get_session_key()[0..16], &m[0..16])?;
        Ok(padding::remove_pkcs7(&plaintext).unwrap())
    }

    fn get_attacker(&self) -> &ParamInjectionAttacker;
    fn get_attacker_mut(&mut self) -> &mut ParamInjectionAttacker<'p>;
    fn get_forged_key(&self) -> Vec<u8>;
    fn get_forged_pubkey(&self, &BigUint) -> BigUint;
    fn transform_params(&self, (BigUint, BigUint, BigUint)) -> (BigUint, BigUint, BigUint);
}

pub struct ParamInjectionAttacker<'p> {
   player: &'p mut DhPlayer,
   s: Vec<u8>
}

impl<'p> ParamInjectionAttacker<'p> {
    pub fn new(player: &mut DhPlayer) -> ParamInjectionAttacker {
        ParamInjectionAttacker {
            player,
            s: vec![],
        }
    }

    fn get_player(&self) -> &DhPlayer {
         self.player
    }

    fn get_player_mut(&mut self) -> &mut DhPlayer {
         self.player
    }

    fn get_session_key(&self) -> &[u8] {
         &self.s
    }

    fn set_session_key(&mut self, session_key: &[u8]) {
         self.s = session_key.to_vec();
    }
}

impl<'p, T> Dh for T where T: ParamInjection<'p> {
    fn generate_session_key(&mut self, other_pubkey: &BigUint) {
        let forged_pubkey = self.get_forged_pubkey(other_pubkey);
        self.get_attacker_mut().get_player_mut().generate_session_key(&forged_pubkey);
        let forged_key = self.get_forged_key();
        self.get_attacker_mut().set_session_key(&Sha256::digest(&forged_key));
    }

    fn send_encrypted_message(&self) -> Result<Vec<u8>, EncryptionOracleError> {
        self.get_attacker().get_player().send_encrypted_message()
    }
}

impl<'p, T> EchoBot for T where T: ParamInjection<'p> {
    fn get_params(&self) -> (BigUint, BigUint, BigUint) {
        let params = self.get_attacker().get_player().get_params();
        self.transform_params(params)
    }
}

pub struct PInjectionAttacker<'p> {
    attacker: ParamInjectionAttacker<'p>,
    p: BigUint,
}

impl<'p> PInjectionAttacker<'p> {
    pub fn new(player: &mut DhPlayer) -> PInjectionAttacker {
        let (p, _g, _pubkey) = player.get_params();
        let attacker = ParamInjectionAttacker::new(player);
        PInjectionAttacker {
            attacker,
            p
        }
    }
}

impl<'p> ParamInjection<'p> for PInjectionAttacker<'p> {
    fn get_attacker(&self) -> &ParamInjectionAttacker {
        &self.attacker
    }

    fn get_attacker_mut(&mut self) -> &mut ParamInjectionAttacker<'p> {
        &mut self.attacker
    }

    fn get_forged_key(&self) -> Vec<u8> {
         vec![0]
    }

    fn get_forged_pubkey(&self, _other_pubkey: &BigUint) -> BigUint {
         self.p.clone()
    }

    fn transform_params(&self, (p, g, _pubkey): (BigUint, BigUint, BigUint)) -> (BigUint, BigUint, BigUint) {
         (p.clone(), g, p)
    }
}

pub struct G1InjectionAttacker<'p> {
    attacker: ParamInjectionAttacker<'p>,
}

impl<'p> G1InjectionAttacker<'p> {
    pub fn new(player: &mut DhPlayer) -> G1InjectionAttacker {
        let attacker = ParamInjectionAttacker::new(player);
        G1InjectionAttacker {
            attacker
        }
    }
}

impl<'p> ParamInjection<'p> for G1InjectionAttacker<'p> {
    fn get_attacker(&self) -> &ParamInjectionAttacker {
        &self.attacker
    }

    fn get_attacker_mut(&mut self) -> &mut ParamInjectionAttacker<'p> {
        &mut self.attacker
    }

    fn get_forged_key(&self) -> Vec<u8> {
         vec![1]
    }

    fn get_forged_pubkey(&self, other_pubkey: &BigUint) -> BigUint {
         other_pubkey.clone()
    }

    fn transform_params(&self, (p, _g, _pubkey): (BigUint, BigUint, BigUint)) -> (BigUint, BigUint, BigUint) {
         (p, One::one(), One::one())
    }
}

pub struct GPInjectionAttacker<'p> {
    attacker: ParamInjectionAttacker<'p>,
}

impl<'p> GPInjectionAttacker<'p> {
    pub fn new(player: &mut DhPlayer) -> GPInjectionAttacker {
        let attacker = ParamInjectionAttacker::new(player);
        GPInjectionAttacker {
            attacker
        }
    }
}

impl<'p> ParamInjection<'p> for GPInjectionAttacker<'p> {
    fn get_attacker(&self) -> &ParamInjectionAttacker {
        &self.attacker
    }

    fn get_attacker_mut(&mut self) -> &mut ParamInjectionAttacker<'p> {
        &mut self.attacker
    }

    fn get_forged_key(&self) -> Vec<u8> {
         vec![0]
    }

    fn get_forged_pubkey(&self, other_pubkey: &BigUint) -> BigUint {
         other_pubkey.clone()
    }

    fn transform_params(&self, (p, _g, _pubkey): (BigUint, BigUint, BigUint)) -> (BigUint, BigUint, BigUint) {
         (p.clone(), p, Zero::zero())
    }
}

pub struct GPMinus1InjectionAttacker<'p> {
    attacker: ParamInjectionAttacker<'p>,
}

impl<'p> GPMinus1InjectionAttacker<'p> {
    pub fn new(player: &mut DhPlayer) -> GPMinus1InjectionAttacker {
        let attacker = ParamInjectionAttacker::new(player);
        GPMinus1InjectionAttacker {
            attacker,
        }
    }
}

impl<'p> ParamInjection<'p> for GPMinus1InjectionAttacker<'p> {
    fn get_attacker(&self) -> &ParamInjectionAttacker {
        &self.attacker
    }

    fn get_attacker_mut(&mut self) -> &mut ParamInjectionAttacker<'p> {
        &mut self.attacker
    }

    fn get_forged_key(&self) -> Vec<u8> {
         vec![1]
    }

    fn get_forged_pubkey(&self, _other_pubkey: &BigUint) -> BigUint {
         One::one()
    }

    fn transform_params(&self, (p, _g, _pubkey): (BigUint, BigUint, BigUint)) -> (BigUint, BigUint, BigUint) {
         (p.clone(), p - 1u8, One::one())
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
    fn test_mitm_p_echo_bot() {
        let mut alice = DhPlayer::new_with_message("PING");
        let mut bob = DhPlayer::new_with_message("PONG");

        let mut eve = PInjectionAttacker::new(&mut alice);

        assert_eq!(bob.get_msg_from(&mut eve).unwrap(), b"PING");
        assert_eq!(eve.intercept_msg().unwrap(), b"PING");
    }

    #[test]
    fn test_mitm_g_1_echo_bot() {
        let mut alice = DhPlayer::new_with_message("PING");
        let mut bob = DhPlayer::new_with_message("PONG");

        let mut eve = G1InjectionAttacker::new(&mut alice);

        assert_eq!(bob.get_msg_from(&mut eve).unwrap(), b"PING");
        assert_eq!(eve.intercept_msg().unwrap(), b"PING");
    }

    #[test]
    fn test_mitm_g_p_echo_bot() {
        let mut alice = DhPlayer::new_with_message("PING");
        let mut bob = DhPlayer::new_with_message("PONG");

        let mut eve = GPInjectionAttacker::new(&mut alice);

        assert_eq!(bob.get_msg_from(&mut eve).unwrap(), b"PING");
        assert_eq!(eve.intercept_msg().unwrap(), b"PING");
    }

    #[test]
    fn test_mitm_g_p_minus_1_echo_bot() {
        let mut alice = DhPlayer::new_with_message("PING");
        let mut bob = DhPlayer::new_with_message("PONG");

        let mut eve = GPMinus1InjectionAttacker::new(&mut alice);

        assert_eq!(bob.get_msg_from(&mut eve).unwrap(), b"PING");
        assert_eq!(eve.intercept_msg().unwrap(), b"PING");
    }
}
