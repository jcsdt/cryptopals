use std::num::Wrapping;
use std::time;
use std::time::UNIX_EPOCH;

const N: usize = 624;
const M: usize = 397;
const LOWER_MASK: Wrapping<u32> = Wrapping((1 << 31) - 1);
const UPPER_MASK: Wrapping<u32> = Wrapping(!((1 << 31) - 1));
const F: Wrapping<u32> = Wrapping(1812433253);

pub struct MT19937 {
    state: [Wrapping<u32>; N],
    index: usize,
}

impl MT19937 {
    pub fn new(seed: u32) -> MT19937 {
        let mut state = [Wrapping(0); N];
        state[0] = Wrapping(seed);
        for i in 1..N {
            state[i] = F * (state[i - 1] ^ (state[i - 1] >> 30)) + Wrapping(i as u32);
        }

        MT19937 {
            state,
            index: N,
        }
    }

    pub fn gen(&mut self) -> u32 {
        if self.index >= self.state.len() {
            self.twist();
        }

        let Wrapping(mut y) = self.state[self.index];
        y = y ^ (y >> 11);
        y = y ^ ((y << 7) & 0x9D2C5680);
        y = y ^ ((y << 15) & 0xEFC60000);
        y = y ^ (y >> 18);
        
        self.index += 1;
        y
    }

    fn twist(&mut self) {
        for i in 0..N {
            let Wrapping(x) = (self.state[i] & UPPER_MASK)
                + (self.state[(i + 1) % N] & LOWER_MASK);
            let mut x_a = x >> 1;
            if x % 2 != 0 {
                x_a = x_a ^ 0x9908B0DF;
            }
            self.state[i] = self.state[(i + M) % N] ^ Wrapping(x_a);
        }
        self.index = 0;
    }
}

pub fn crack_mt199937_seed(mt: &mut MT19937, before: time::SystemTime, after: time::SystemTime) -> u32 {
   let n = mt.gen();
   for s in before.duration_since(UNIX_EPOCH).unwrap().as_secs() .. after.duration_since(UNIX_EPOCH).unwrap().as_secs() {
        let mut mt2 = MT19937::new(s as u32);
        let m = mt2.gen();
        if n == m {
            return s as u32;
        }
   }

   0
}


#[cfg(test)]
mod tests {
    use super::*;

    use std::fs::File;
    use std::io::prelude::*;
    use std::thread;
    use std::time::SystemTime;

    use rand::{thread_rng, Rng};

    #[test]
    fn test_mt19937() {
        let mut f = File::open("./data/mt19937.out").expect("file not found");

        let mut contents = String::new();
        f.read_to_string(&mut contents).expect("something went wrong reading the file");
        let test_outputs = contents.split("\n").filter(|s| !s.is_empty()).map(|s| s.parse::<u32>().unwrap()).collect::<Vec<u32>>();

        let mut mt = MT19937::new(5489);
        for i in 0..1000 {
            assert_eq!(mt.gen(), test_outputs[i])
        }
    }

    #[test]
    #[ignore]
    fn test_crack_mt19937() {
        let before = SystemTime::now();
        let s = thread_rng().gen_range(40, 200);
        thread::sleep(time::Duration::from_secs(s));
        let seed = SystemTime::now().duration_since(time::UNIX_EPOCH).unwrap().as_secs() as u32;
        let mut mt = MT19937::new(seed);
        let s = thread_rng().gen_range(40, 200);
        thread::sleep(time::Duration::from_secs(s));
        let recovered_seed = crack_mt199937_seed(&mut mt, before, SystemTime::now());
        assert_eq!(recovered_seed, seed);
    }
}
