extern crate ring;
extern crate zstd;

use std::io::{self, Read, BufReader, BufWriter, Cursor};
use std::io::prelude::*;
use std::fs::File;


use ring::aead::*;
use ring::pbkdf2::*;
use ring::rand::{SystemRandom, SecureRandom};
use std::num::NonZeroU32;


use zstd::block::Compressor;

mod enc;

//fn crypto() {
//    let password = b"p@ssw0rd";
//    let key_len = AES_256_GCM.key_len();
//    let mut key = vec![0; key_len];
//    let salt = [0, 1, 2, 3, 4, 5, 6, 7]; // would be account_id
//    let iterations = unsafe { NonZeroU32::new_unchecked(100) };
//
//    derive(PBKDF2_HMAC_SHA512, iterations, &salt, &password[..], &mut key);
//
//    let unbound_key = UnboundKey::new(&AES_256_GCM, &key).expect("Error creating unbound key");
//
//    // Fill nonce with random data
//    let rand = SystemRandom::new();
//
//    let less_safe_key = LessSafeKey::new(unbound_key);
//
//    let mut plaintext_1 = b"my secret message".to_vec();
//    let mut plaintext_2 = b"my second secret message".to_vec();
//
//    println!("PLAINTEXT: {} {}", String::from_utf8(plaintext_1.clone()).unwrap(), String::from_utf8(plaintext_2.clone()).unwrap());
//
//    let mut cipher_text = Vec::new();
//    let mut lens = Vec::new();
//
//    let mut nonce_buff1 = [0; 12];
//    rand.fill(&mut nonce_buff1).expect("Error filling nonce");
//    let nonce1 = Nonce::assume_unique_for_key(nonce_buff1);
//
//    less_safe_key.seal_in_place_append_tag(nonce1, Aad::empty(), &mut plaintext_1).expect("Could not seal");
//    lens.push(plaintext_1.len());
//    cipher_text.extend(plaintext_1);
//
//    let mut nonce_buff2 = [0; 12];
//    rand.fill(&mut nonce_buff2).expect("Error filling nonce");
//    let nonce2 = Nonce::assume_unique_for_key(nonce_buff2);
//
//    less_safe_key.seal_in_place_append_tag(nonce2, Aad::empty(), &mut plaintext_2).expect("Could not seal");
//    lens.push(plaintext_2.len());
//    cipher_text.extend(plaintext_2);
//
//    println!("LEN 1: {}", lens[0]);
//    println!("LEN 2: {}", lens[1]);
//    println!("CIPHERTEXT: {:?}", cipher_text);
//
//    let nonce1 = Nonce::assume_unique_for_key(nonce_buff1);
//    let decrypted = less_safe_key.open_within(nonce1, Aad::empty(), &mut cipher_text[0..lens[0]], 0..).expect("Error opening");
//
//    println!("DECRYPT: {}", String::from_utf8(decrypted.to_vec()).unwrap());
//
//    let nonce2 = Nonce::assume_unique_for_key(nonce_buff2);
//    let decrypted = less_safe_key.open_within(nonce2, Aad::empty(), &mut cipher_text[lens[0]..], 0..).expect("Error opening");
//
//    println!("DECRYPT: {}", String::from_utf8(decrypted.to_vec()).unwrap());
//}

use std::env;

fn main() {
    let mut stdin = BufReader::new(io::stdin());
    let mut stdout = BufWriter::new(io::stdout());
    let mut compress = Compressor::new();

    let args = env::args().collect::<Vec<_>>();

    let compress_level = args[1].parse::<i32>().expect("Didn't pass compress level");

    loop {
        let mut buff = vec![0; 262144];
        let res = stdin.read(&mut buff);

        if let Err(e) = res {
            eprintln!("Error reading from STDIN: {:?}", e);
            break;
        }

        let amt = res.unwrap();

        if amt == 0 {
            break;
        }

        let res = compress.compress(&buff[0..amt], compress_level);

        if let Err(e) = res {
            eprintln!("Error compressing block: {:?}", e);
            break;
        }

        let buff = res.unwrap();

        let res = stdout.write_all(buff.as_slice());

        if let Err(e) = res {
            eprintln!("Error writing to STDOUT: {:?}", e);
            break;
        }
    }



}
