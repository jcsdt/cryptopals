# RustCrypto hashes [![Build Status](https://travis-ci.org/RustCrypto/hashes.svg?branch=master)](https://travis-ci.org/RustCrypto/hashes)
Collection of cryptographic hash functions written in pure Rust.

All algorithms split into separate crates and implemented using traits from
[`digest`](https://docs.rs/digest/0.5.2/digest/) crate. Additionally all crates
do not require the standard library (i.e. `no_std` capable) and can
be easily used for bare-metal programming.

## Supported algorithms
**Note:** For new applications, or where compatibility with other existing
standards is not a primary concern, we strongly recommend either BLAKE2, SHA-2
or SHA-3.

| Name     | Alt name   | Crates.io  | Documentation  | [Security Level] |
| ------------- |:-------------:| :-----:| :-----:| :-----:|
| [BLAKE2](https://en.wikipedia.org/wiki/BLAKE_(hash_function)#BLAKE2) |   | [![crates.io](https://img.shields.io/crates/v/blake2.svg)](https://crates.io/crates/blake2) | [![Documentation](https://docs.rs/blake2/badge.svg)](https://docs.rs/blake2) | :green_heart: |
| [GOST94](https://en.wikipedia.org/wiki/GOST_(hash_function)) | GOST R 34.11-94  | [![crates.io](https://img.shields.io/crates/v/gost94.svg)](https://crates.io/crates/gost94) |  [![Documentation](https://docs.rs/gost94/badge.svg)](https://docs.rs/gost94) | :yellow_heart: |
| [Grøstl](https://en.wikipedia.org/wiki/Grøstl) | Groestl  | [![crates.io](https://img.shields.io/crates/v/groestl.svg)](https://crates.io/crates/groestl) |  [![Documentation](https://docs.rs/groestl/badge.svg)](https://docs.rs/groestl) | :green_heart: |
| [MD2](https://en.wikipedia.org/wiki/MD2_(cryptography)) |    | [![crates.io](https://img.shields.io/crates/v/md2.svg)](https://crates.io/crates/md2) |  [![Documentation](https://docs.rs/md2/badge.svg)](https://docs.rs/md2) | :broken_heart: |
| [MD4](https://en.wikipedia.org/wiki/MD4) |    | [![crates.io](https://img.shields.io/crates/v/md4.svg)](https://crates.io/crates/md4) |  [![Documentation](https://docs.rs/md4/badge.svg)](https://docs.rs/md4) | :broken_heart: |
| [MD5](https://en.wikipedia.org/wiki/MD5) [:exclamation:](#crate-names) |   | [![crates.io](https://img.shields.io/crates/v/md-5.svg)](https://crates.io/crates/md-5) | [![Documentation](https://docs.rs/md-5/badge.svg)](https://docs.rs/md-5) | :broken_heart: |
| [RIPEMD-160](https://en.wikipedia.org/wiki/RIPEMD) |    | [![crates.io](https://img.shields.io/crates/v/ripemd160.svg)](https://crates.io/crates/ripemd160) |  [![Documentation](https://docs.rs/ripemd160/badge.svg)](https://docs.rs/ripemd160) | :green_heart: |
| [SHA-1](https://en.wikipedia.org/wiki/SHA-1) [:exclamation:](#crate-names) |    | [![crates.io](https://img.shields.io/crates/v/sha-1.svg)](https://crates.io/crates/sha-1) | [![Documentation](https://docs.rs/sha-1/badge.svg)](https://docs.rs/sha-1) | :broken_heart: |
| [SHA-2](https://en.wikipedia.org/wiki/SHA-2) |    | [![crates.io](https://img.shields.io/crates/v/sha2.svg)](https://crates.io/crates/sha2) |  [![Documentation](https://docs.rs/sha2/badge.svg)](https://docs.rs/sha2) | :green_heart: |
| [SHA-3](https://en.wikipedia.org/wiki/SHA-3) |  Keccak  | [![crates.io](https://img.shields.io/crates/v/sha3.svg)](https://crates.io/crates/sha3) |  [![Documentation](https://docs.rs/sha3/badge.svg)](https://docs.rs/sha3) | :green_heart: |
| [Streebog](https://en.wikipedia.org/wiki/Streebog) |  GOST R 34.11-2012  | [![crates.io](https://img.shields.io/crates/v/streebog.svg)](https://crates.io/crates/streebog) |  [![Documentation](https://docs.rs/streebog/badge.svg)](https://docs.rs/streebog) | :yellow_heart: |
| [Whirlpool](https://en.wikipedia.org/wiki/Whirlpool_(cryptography)) |    | [![crates.io](https://img.shields.io/crates/v/whirlpool.svg)](https://crates.io/crates/whirlpool) |  [![Documentation](https://docs.rs/whirlpool/badge.svg)](https://docs.rs/whirlpool) | :green_heart: |

[Security Level]: https://en.wikipedia.org/wiki/Hash_function_security_summary

### Security Level Legend

The following describes the security level ratings associated with each
hash function (i.e. algorithms, not the specific implementation):

| Heart | Description |
|-------|-------------|
| :green_heart: | No known successful attacks |
| :yellow_heart: | Theoretical break: security lower than claimed |
| :broken_heart: | Attack demonstrated in practice: avoid if at all possible |

### Minimum Rust version
All crates in this repository support Rust 1.21 or higher. In future
minimally supported version of Rust can be changed, but it will be done with
the minor version bump.

Older crate versions support older Rust as well up to 1.13.

### Crate names

Whenever possible crates are published under the the same name as the crate
folder. Owners of `md5` and `sha1` crates refused
([1](https://github.com/stainless-steel/md5/pull/2),
[2](https://github.com/mitsuhiko/rust-sha1/issues/17)) to participate in this
project. This is why crates marked by :exclamation: are published under
`md-5` and `sha-1` names respectively.

## Usage
Let us demonstrate how to use crates in this repository using BLAKE2b as an
example.

First add `blake2` crate to your `Cargo.toml`:

```toml
[dependencies]
blake2 = "0.7"
```

`blake2` and other crates re-export
[`Digest`](https://docs.rs/digest/0.5.2/digest/trait.Digest.html) trait for
convenience, so you don't have to add `digest` crate as an explicit dependency.

Now you can write the following code:

```Rust
use blake2::{Blake2b, Digest};

let mut hasher = Blake2b::new();
let data = b"Hello world!";
hasher.input(data);
// `input` can be called repeatedly
hasher.input("String data".as_bytes());
// Note that calling `result()` consumes hasher
let hash = hasher.result();
println!("Result: {:x}", hash);
```

`hash` has type [`GenericArray<u8, U64>`](http://fizyk20.github.io/generic-array/generic_array/struct.GenericArray.html), which is a generic alternative to `[u8; 64]`.

Also you can use the following approach if the whole message is available:

```Rust
let hash = Blake2b::digest(b"my message");
println!("Result: {:x}", hash);
```

### Hashing `Read`able objects

If you want to hash data from [`Read`](https://doc.rust-lang.org/std/io/trait.Read.html)
trait (e.g. from file) you can enable `std` feature in digest crate:

```toml
[dependencies]
blake2 = "0.7"
digest = { version = "0.7", features = ["std"]}
```

And use `digest_reader` method which will compute hash by reading data using
1 KB blocks:

```Rust
use blake2::{Blake2b, Digest};
use std::fs;

let mut file = fs::File::open(&path)?;
let hash = Blake2b::digest_reader(&mut file)?;
println!("{:x}\t{}", hash, path);
```

### Hash-based Message Authentication Code (HMAC)

One of the common tasks for cryptographic hash functions is generation of
[Message Authentication Codes](https://en.wikipedia.org/wiki/Message_authentication_code)
(MAC). In RustCrypto all MAC functions represented using `Mac` trait from
[`crypto-mac`](https://crates.io/crates/crypto-mac) crate. Some hash functions
provide `Mac` implementations (e.g. BLAKE2), but for others you can use generically
implemented [HMAC](https://en.wikipedia.org/wiki/Hash-based_message_authentication_code)
from [`hmac`](https://crates.io/crates/hmac) crate.

To demonstrate how to use HMAC, lets use SHA256 as an example. First add the
following dependencies to your crate:

```toml
[dependencies]
hmac = "0.5"
sha2 = "0.7"
```

To get the authentication code:

```Rust
extern crate hmac;
extern crate sha2;

use sha2::Sha256;
use hmac::{Hmac, Mac};

// Create `Mac` trait implementation, namely HMAC-SHA256
let mut mac = Hmac::<Sha256>::new(b"my secret and secure key").unwrap();
mac.input(b"input message");

// `result` has type `MacResult` which is a thin wrapper around array of
// bytes for providing constant time equality check
let result = mac.result();
// To get underlying array use `code` method, but be carefull, since
// incorrect use of the code value may permit timing attacks which defeat
// the security provided by the `MacResult`
let code_bytes = result.code();
```

To verify the message:

```rust,ignore
let mut mac = Hmac::<Sha256>::new(b"my secret and secure key").unwrap();

mac.input(b"input message");

// `verify` will return `Ok(())` if code is correct, `Err(MacError)` otherwise
mac.verify(&code_bytes).unwrap();
```

### Generic code

You can write generic code over `Digest` trait which will work over different
hash functions:

```Rust
use digest::Digest;

// Toy example, do not use it in practice!
fn hash_password<D: Digest>(password: &str, salt: &str, output: &mut [u8]) {
    let mut hasher = D::new();
    hasher.input(password.as_bytes());
    hasher.input(b"$");
    hasher.input(salt.as_bytes());
    output.copy_from_slice(hasher.result().as_slice())
}

use blake2::Blake2b;
use sha2::Sha256;

hash_password::<Blake2b>("my_password", "abcd", &mut buf);
hash_password::<Sha256>("my_password", "abcd", &mut buf);
```

## License

All crates licensed under either of

 * [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
 * [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
