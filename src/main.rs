extern crate clap;
extern crate ring;
extern crate zstd;
#[macro_use]
extern crate serde_derive;
extern crate rmp_serde as rmps;
extern crate serde;

mod enc;

use zstd::block::{Compressor, Decompressor};
use clap::{Arg, App};
use ring::rand::{SystemRandom, SecureRandom};
use serde::{Deserialize, Serialize};
use rmps::{Deserializer, Serializer};
use byteorder::{ReadBytesExt, WriteBytesExt, BE};

use std::io::*;
use std::collections::HashMap;
use std::fs;

use enc::{Sealer, Opener};

#[derive(Debug, PartialEq, Deserialize, Serialize)]
struct FileHeader {
    salt: String,
    nonce_seed: Vec<u8>,
    comments: HashMap<String, String>
}

const VERSION : u64 = 1;
const BLOCK_SIZE : usize = 4_048_576;

fn encrypt(mut input_reader : impl Read, mut output_writer : &mut impl Write, password : &str, salt : &str) {
    let rand = SystemRandom::new();
    let mut buff = vec![0; BLOCK_SIZE];
    let mut compress = Compressor::new();
    let mut nonce_seed = [0; 8];

    rand.fill(&mut nonce_seed).expect("Error filling random nonce");

    let mut sealer = Sealer::new(password, salt.as_bytes(), nonce_seed);

    let file_header = FileHeader {
        salt: String::from(salt),
        nonce_seed: nonce_seed.to_vec(),
        comments: HashMap::new()

    };

    // write out the version
    // this is kept outside the FileHeader so we can read it in an independent way
    output_writer.write_u64::<BE>(VERSION).expect("Error writing version");

    // serialize and write out the file's header
    file_header.serialize(&mut Serializer::new(&mut output_writer)).expect("Error writing file header");

    loop {
        let res = input_reader.read(&mut buff);

        if let Err(e) = res {
            eprintln!("Error reading input: {:?}", e);
            break;
        }

        let amt = res.unwrap();

        dbg!("AMT: {}", amt);

        if amt == 0 {
            break;
        }

        let plaintext = compress.compress(&buff[0..amt], 2).expect("Error compressing input");

        dbg!("PT: {}", plaintext.len());

        let ciphertext = sealer.seal(plaintext);

        output_writer.write_all(&ciphertext).expect("Error writing to output");
    }

}

fn decrypt(mut input_reader : impl Read, output_writer : &mut impl Write, password : &str) {
    // read in the version of the file
    let version = input_reader.read_u64::<BE>().expect("Unable to read version");

    if version != VERSION {
        panic!("Unsupported version: {}", version);
    }

    // read in the file header
    let file_header : FileHeader = Deserialize::deserialize(&mut Deserializer::new(&mut input_reader)).expect("Error reading file header");

    dbg!(file_header.salt.chars());

    let mut nonce_seed = [0; 8];

    nonce_seed.copy_from_slice(file_header.nonce_seed.as_slice());

    let mut opener = Opener::new(password, file_header.salt.as_bytes(), nonce_seed);
    let mut decompress = Decompressor::new();

    loop {
        let block_size = input_reader.read_u32::<BE>();

        // we only get an error when we've reached the end of the buffer
        if block_size.is_err() {
            break;
        }

        let block_size = block_size.unwrap();

        dbg!("BLOCK_SIZE: {}", block_size);

        let mut buff = vec![0; block_size as usize];
        let res = input_reader.read_exact(&mut buff);

        if let Err(e) = res {
            eprintln!("Error reading input: {:?}", e);
            break;
        }

        let plaintext = opener.open(buff);

        dbg!("PT: {}", plaintext.len());

        let plaintext = decompress.decompress(&plaintext, BLOCK_SIZE).expect("Error decompressing input");

        output_writer.write_all(&plaintext).expect("Error writing to output");
    }
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

    // construct the input reader from either STDIN or from the file
    let input_reader : Box<dyn BufRead> = if input == "-" {
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


    if matches.is_present("decrypt") {
        eprintln!("Attempting to decrypt...");

        decrypt(input_reader, &mut output_writer, password);
    } else {
        eprintln!("Attempting to encrypt...");

        let salt = matches.value_of("salt").expect("Must supply salt!");

        encrypt(input_reader, &mut output_writer, password, salt);
    }
}

#[cfg(test)]
mod main_tests {
    use std::io::{Read, Write, Cursor};
    use ring::rand::{SystemRandom, SecureRandom};

    fn encrypt_decrypt_test(buff_size : usize) {
        let rand = SystemRandom::new();

        let mut input_buffer = vec![0; buff_size];

        rand.fill(&mut input_buffer);

        let mut input_reader = Cursor::new(input_buffer);

        let mut encrypt_buffer = Vec::new();

        crate::encrypt(&mut input_reader, &mut encrypt_buffer, "password", "salt");

        let encrypt_reader = Cursor::new(encrypt_buffer);
        let mut plaintext_buffer = Vec::new();

        crate::decrypt(encrypt_reader, &mut plaintext_buffer, "password");

        assert_eq!(plaintext_buffer, input_reader.into_inner());
    }

    #[test] fn test_zero_block_encrypt() { encrypt_decrypt_test(0); }
    #[test] fn test_small_encrypt() { encrypt_decrypt_test(10); }
    #[test] fn test_single_block_encrypt() { encrypt_decrypt_test(crate::BLOCK_SIZE); }
    #[test] fn test_two_blocks_encrypt() { encrypt_decrypt_test(crate::BLOCK_SIZE * 2); }
    #[test] fn test_ten_blocks_encrypt() { encrypt_decrypt_test(crate::BLOCK_SIZE * 10); }
}
