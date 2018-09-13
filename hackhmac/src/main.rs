#![feature(duration_as_u128)]

extern crate hex;
extern crate requests;

use std::collections::HashMap;
use std::time::SystemTime;

fn main() {
    let mut mac = [0u8; 20];
    for i in 0..20 {
        let mut times: HashMap<u8, Vec<_>> = HashMap::new();

        for _ in 0..10 {
            for b in 0..256u32 {
                mac[i] = b as u8;
                let url = format!("http://localhost:3000/hmac?content=helloworld&sig={}", hex::encode(mac));
                let now = SystemTime::now();
                let response = requests::get(url).unwrap();
                let millis = now.elapsed().unwrap().as_nanos();

                times.entry(b as u8).and_modify(|v| { v.push(millis); }).or_insert(vec![millis]);

                if response.status_code() == requests::StatusCode::Ok {
                    println!("Found signature {}", hex::encode(mac)); 
                    std::process::exit(0);
                }
            }
        }

        let mut candidate = 0u8;
        let mut  max_median = 0;
        for (&b, val) in times.iter_mut() {
            val.sort();
            let m = val[val.len() / 2 + 1];
            if m > max_median {
                max_median = m;
                candidate = b;
            }
        }

        println!("{} {}", candidate, max_median);
        mac[i] = candidate;
    }

    println!("Found nothing..."); 
    std::process::exit(1);
}
