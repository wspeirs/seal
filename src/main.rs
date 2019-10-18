extern crate clap;
extern crate ring;
extern crate zstd;

mod enc;

use zstd::block::{Compressor, Decompressor};
use clap::{Arg, App, SubCommand};
use ring::rand::{SystemRandom, SecureRandom};

use std::env;
use std::io::*;
use std::collections::HashMap;
use std::fs;

use enc::{Sealer, Opener};

struct FileHeader {
    version: u32,
    salt: Vec<u8>,
    nonce_seed: Vec<u8>,
    comments: HashMap<String, String>
}


fn main() {
    let matches = App::new("Seal")
        .version("1.0")
        .author("William Speirs <bill.speirs@gmail.com>")
        .about("Compresses and encrypts data")
        .arg(Arg::with_name("input")
            .short("i")
            .long("input")
            .value_name("FILE")
            .help("Input (plaintext or ciphertext)")
            .takes_value(true))
        .arg(Arg::with_name("output")
            .short("o")
            .long("output")
            .value_name("FILE")
            .help("Output (plaintext or ciphertext)")
            .takes_value(true))
        .arg(Arg::with_name("password")
            .short("p")
            .long("password")
            .value_name("PASSWORD")
            .required(true)
            .help("The password used to encrypt or decrypt. Keep this secret!!!")
            .takes_value(true))
        .arg(Arg::with_name("salt")
            .short("s")
            .long("salt")
            .value_name("SALT")
            .help("The salt used to derive the key. No need to keep this secret.")
            .takes_value(true))
        .arg(Arg::with_name("encrypt")
            .conflicts_with("decrypt")
            .short("e")
            .long("encrypt")
            .help("Encrypts the input, and writes ciphertext to the output"))
        .arg(Arg::with_name("decrypt")
            .conflicts_with("encrypt")
            .short("d")
            .long("decrypt")
            .help("Decrypts the input, and writes plaintext to the output"))
        .arg(Arg::with_name("v")
            .short("v")
            .multiple(true)
            .help("Sets the level of verbosity"))
        .get_matches();


    let input = matches.value_of("input").unwrap_or("-");
    let output = matches.value_of("output").unwrap_or("-");
    let password = matches.value_of("password").expect("Must supply a password!");
    let encrypt = matches.is_present("encrypt");

    // construct the input reader from either STDIN or from the file
    let mut input_reader : Box<dyn BufRead> = if input == "-" {
        Box::new(BufReader::new(stdin()))
    } else {
        Box::new(BufReader::new(fs::OpenOptions::new()
            .read(true)
            .write(false)
            .create(false)
            .open(input).expect("Error opening input file")))
    };

    // construct the output writer from either STDOUT or from the file
    let mut output_writer : Box<dyn Write> = if output == "-" {
        Box::new(BufWriter::new(stdout()))
    } else {
        Box::new(BufWriter::new(fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(output).expect("Error opening output file")))
    };

    let mut buff = vec![0; 4_048_576];
    let mut rand = SystemRandom::new();

    if encrypt {
        let salt = matches.value_of("salt").expect("Must supply salt!");
        let mut compress = Compressor::new();
        let mut nonce_seed = [0; 8];

        rand.fill(&mut nonce_seed);

        let mut sealer = Sealer::new(password, salt.as_bytes(), nonce_seed);

        loop {
            let res = input_reader.read(&mut buff);

            if let Err(e) = res {
                eprintln!("Error reading input: {:?}", e);
                break;
            }

            let amt = res.unwrap();

            if amt == 0 {
                break;
            }

            let plaintext = compress.compress(&buff[0..amt], 2).expect("Error compressing input");
            let ciphertext = sealer.seal(plaintext);

            output_writer.write_all(&ciphertext).expect("Error writing to output");
        }
    } else {
        let mut decompress = Decompressor::new();
//        let mut opener = Opener::new(password, salt.as_bytes(), [1,2,3,4,5,6,7,8]);

    }

}
