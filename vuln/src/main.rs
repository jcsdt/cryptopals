extern crate iron;
extern crate hex;
extern crate router;
extern crate lib;
extern crate urlencoded;

use std::{thread, time};

use iron::prelude::*;
use iron::status;
use router::Router;
use lib::mac::hmac_sha1;
use urlencoded::UrlEncodedQuery;

const SECRET: [u8; 16] = [0x00, 0x02, 0xb8, 0xff, 0x65, 0x87, 0x8a, 0x7e, 0x11, 0x2c, 0xef, 0xc8, 0xb1, 0x51, 0x9d, 0x4a];

fn insecure_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    for i in 0..a.len() {
        if a[i] != b[i] {
            return false;
        }

        thread::sleep(time::Duration::from_micros(500));
    }
    true
}

fn main() {

    let mut router = Router::new();

    router.get("/hmac", check_hmac, "hmac");

    fn check_hmac(request: &mut Request) -> IronResult<Response> {
        match request.get_ref::<UrlEncodedQuery>() {
            Ok(hashmap) => {
                let hmac = hmac_sha1(&SECRET, hashmap.get("content").and_then(|ref v| Some(v[0].clone())).unwrap_or(String::from("")).as_bytes());
                if insecure_compare(&hmac, &hex::decode(hashmap.get("sig").and_then(|ref v| Some(v[0].clone())).unwrap_or(String::from(""))).unwrap_or_else(|_| vec![])) {
                    Ok(Response::with((status::Ok, "")))
                } else {
                    Ok(Response::with((status::InternalServerError, "")))
                }
            },
            Err(ref _e) => Ok(Response::with((status::BadRequest, ""))) 
        }
    }

    Iron::new(router).http("localhost:3000").unwrap();
}
