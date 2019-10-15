extern crate libflate;
extern crate ring;

use std::io::{self, Read, BufReader, BufWriter, Cursor};
use std::io::prelude::*;
use std::fs::File;
use libflate::gzip;


use ring::aead::*;
use ring::pbkdf2::*;
use ring::rand::{SystemRandom, SecureRandom};
use std::num::NonZeroU32;


fn main() {
    let password = b"p@ssw0rd";
    let key_len = AES_256_GCM.key_len();
    let mut key = vec![0; key_len];
    let salt = [0, 1, 2, 3, 4, 5, 6, 7]; // would be account_id
    let iterations = unsafe { NonZeroU32::new_unchecked(100) };

    derive(PBKDF2_HMAC_SHA512, iterations, &salt, &password[..], &mut key);

    let unbound_key = UnboundKey::new(&AES_256_GCM, &key).expect("Error creating unbound key");
    
    // Fill nonce with random data
    let rand = SystemRandom::new();

    let less_safe_key = LessSafeKey::new(unbound_key);

    let mut plaintext_1 = b"my secret message".to_vec();
    let mut plaintext_2 = b"my second secret message".to_vec();

    println!("PLAINTEXT: {} {}", String::from_utf8(plaintext_1.clone()).unwrap(), String::from_utf8(plaintext_2.clone()).unwrap());

    let mut cipher_text = Vec::new();
    let mut lens = Vec::new();

    let mut nonce_buff1 = [0; 12];
    rand.fill(&mut nonce_buff1).expect("Error filling nonce");
    let nonce1 = Nonce::assume_unique_for_key(nonce_buff1);

    less_safe_key.seal_in_place_append_tag(nonce1, Aad::empty(), &mut plaintext_1).expect("Could not seal");
    lens.push(plaintext_1.len());
    cipher_text.extend(plaintext_1);

    let mut nonce_buff2 = [0; 12];
    rand.fill(&mut nonce_buff2).expect("Error filling nonce");
    let nonce2 = Nonce::assume_unique_for_key(nonce_buff2);

    less_safe_key.seal_in_place_append_tag(nonce2, Aad::empty(), &mut plaintext_2).expect("Could not seal");
    lens.push(plaintext_2.len());
    cipher_text.extend(plaintext_2);

    println!("LEN 1: {}", lens[0]);
    println!("LEN 2: {}", lens[1]);
    println!("CIPHERTEXT: {:?}", cipher_text);

    let nonce1 = Nonce::assume_unique_for_key(nonce_buff1);
    let decrypted = less_safe_key.open_within(nonce1, Aad::empty(), &mut cipher_text[0..lens[0]], 0..).expect("Error opening");

    println!("DECRYPT: {}", String::from_utf8(decrypted.to_vec()).unwrap());

    let nonce2 = Nonce::assume_unique_for_key(nonce_buff2);
    let decrypted = less_safe_key.open_within(nonce2, Aad::empty(), &mut cipher_text[lens[0]..], 0..).expect("Error opening");

    println!("DECRYPT: {}", String::from_utf8(decrypted.to_vec()).unwrap());
}

//fn main() {
//    let mut stdin = BufReader::new(io::stdin());
//    let mut stdout = BufWriter::new(io::stdout());
//    let mut buff = Cursor::new(Vec::new());
//
//    let mut encoder = gzip::Encoder::new(buff).unwrap();
//
//    io::copy(&mut stdin, &mut encoder);
//    let mut res = encoder.finish().into_result().unwrap();
//
//    res.set_position(0);
//
//    let mut decoder = gzip::Decoder::new(res).expect("Read GZIP header failed");
//
//    io::copy(&mut decoder, &mut stdout);
//}
