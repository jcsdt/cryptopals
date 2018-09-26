extern crate num_bigint;
extern crate num_traits;
extern crate sha2;

use rand;
use self::num_bigint::{ToBigUint, BigUint, RandBigInt};
use self::num_traits::{Zero, One};
use self::sha2::{Sha256, Digest};

pub struct DhPlayer {
    p: BigUint,
    pubkey: BigUint,
    random: BigUint,
    s: Vec<u8>,
}

impl DhPlayer {
    pub fn new() -> DhPlayer {
        let p = BigUint::parse_bytes(b"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 16).unwrap();
        let g = 2u32.to_biguint().unwrap();
        let random = rand::thread_rng().gen_biguint_below(&p);
        let pubkey = modexp(&g, &random, &p);
        DhPlayer {
            p,
            pubkey,
            random,
            s: vec![],
        }
    }

    pub fn get_pubkey(&self) -> &BigUint {
        &self.pubkey
    }

    pub fn get_session_key(&self) -> &[u8] {
        &self.s
    }

    pub fn generate_session_key(&mut self, other_pubkey: &BigUint) {
       self.s = Sha256::digest(&modexp(other_pubkey, &self.random, &self.p).to_bytes_be()).to_vec();
    }
}

fn modexp(base: &BigUint, exp: &BigUint, m: &BigUint) -> BigUint {
    let mut a = base % m;
    let mut r = if exp % 2u8 == One::one() { a.clone() } else { Zero::zero() };

    let mut i = 1;
    while i <= exp.bits() {
        a = (&a * &a) % m;
        if (exp >> i) % 2u8 == One::one() {
            r *= a.clone();
            r %= m;
        }
        i += 1; 
    }

    r
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
