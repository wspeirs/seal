#[macro_use]
extern crate log;
extern crate fern;
extern crate chrono;
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

use std::io::{Read, Write, BufReader, BufRead, BufWriter, stdin, stdout};
use std::collections::HashMap;
use std::fs;
use std::error::Error;

use enc::{Sealer, Opener};

#[derive(Debug, PartialEq, Deserialize, Serialize)]
struct FileHeader {
    salt: String,
    nonce_seed: Vec<u8>,
    comments: HashMap<String, String>
}

const VERSION: u64 = 1;
const BLOCK_SIZE: usize = 4_048_576;
const COMPRESS_STR: &str = "COMPRESSED_ONLY";

fn read_file_header(input_reader: &mut (dyn Read)) -> Result<FileHeader, Box<dyn Error>> {
    // read in the version of the file
    let version = input_reader.read_u64::<BE>().or_else(|e| { error!("Unable to read version"); Err(e) })?;

    if version != VERSION {
        error!("Unsupported file version: {}", version);
        return Err(Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, "Unsupported file version")));
    }

    // read in the file header
    Ok(Deserialize::deserialize(&mut Deserializer::new(&mut (*input_reader))).expect("Error reading file header"))
}

fn encrypt(input_reader: &mut (dyn Read), output_writer: &mut (dyn Write), password : &str, salt : &str, size_file : Option<&str>) -> Result<(), Box<dyn Error>> {
    let rand = SystemRandom::new();
    let mut buff = vec![0; BLOCK_SIZE];
    let mut compress = Compressor::new();
    let mut nonce_seed = [0; 8];

    rand.fill(&mut nonce_seed).or_else(|e| { error!("Error reading random data"); Err(e) })?;

    let mut sealer = Sealer::new(password, salt.as_bytes(), nonce_seed)?;

    let file_header = FileHeader {
        salt: String::from(salt),
        nonce_seed: nonce_seed.to_vec(),
        comments: HashMap::new()
    };

    // write out the version
    // this is kept outside the FileHeader so we can read it in an independent way
    output_writer.write_u64::<BE>(VERSION)?;

    // serialize and write out the file's header
    file_header.serialize(&mut Serializer::new(&mut (*output_writer)))?;

    let mut original_size = 0;
    let mut compressed_size = 0;

    loop {
        let res = input_reader.read(&mut buff);

        if res.is_err() {
            break;
        }

        let amt = res.unwrap();

        debug!("AMT: {}", amt);

        if amt == 0 {
            break;
        }

        original_size += amt;

        let plaintext = compress.compress(&buff[0..amt], 2).or_else(|e| { error!("Error compressing input"); Err(e) })?;

        debug!("PT: {}", plaintext.len());

        compressed_size += plaintext.len();

        let ciphertext = sealer.seal(plaintext);

        output_writer.write_all(&ciphertext).or_else(|e| { error!("Error writing to output"); Err(e) })?;
    }

    if let Some(path) = size_file {
        let mut file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(path).or_else(|e| { error!("Error opening size info file"); Err(e) })?;

        file.write_all(format!("original={}\n", original_size).as_bytes())?;
        file.write_all(format!("compressed={}\n", compressed_size).as_bytes())?;
    }

    Ok( () )
}

fn decrypt(input_reader: &mut (dyn Read), output_writer: &mut (dyn Write), password: &str, salt: &str, nonce_seed: [u8; 8]) -> Result<(), Box<dyn Error>> {
    let mut opener = Opener::new(password, salt.as_bytes(), nonce_seed)?;
    let mut decompressor = Decompressor::new();

    loop {
        let block_size = input_reader.read_u32::<BE>();

        // we only get an error when we've reached the end of the buffer
        if block_size.is_err() {
            break;
        }

        let block_size = block_size.unwrap();

        debug!("BLOCK_SIZE: {}", block_size);

        let mut buff = vec![0; block_size as usize];
        let res = input_reader.read_exact(&mut buff);

        if res.is_err() {
            break;
        }

        let plaintext = opener.open(buff);

        debug!("PT: {}", plaintext.len());

        let plaintext = decompressor.decompress(&plaintext, BLOCK_SIZE).or_else(|e| { error!("Error decompressing input"); Err(e) })?;

        output_writer.write_all(&plaintext).or_else(|e| { error!("Error writing to output"); Err(e) })?;
    }

    Ok( () )
}

fn compress(input_reader: &mut (dyn Read), output_writer: &mut (dyn Write), size_file : Option<&str>) -> Result<(), Box<dyn Error>> {
    let mut buff = vec![0; BLOCK_SIZE];
    let mut compress = Compressor::new();

    let mut comments = HashMap::new();

    comments.insert("type".to_string(), COMPRESS_STR.to_string());

    let file_header = FileHeader {
        salt: COMPRESS_STR.to_string(),
        nonce_seed: COMPRESS_STR.as_bytes().to_vec(),
        comments: comments
    };

    // write out the version
    // this is kept outside the FileHeader so we can read it in an independent way
    output_writer.write_u64::<BE>(VERSION)?;

    // serialize and write out the file's header
    file_header.serialize(&mut Serializer::new(&mut (*output_writer)))?;

    let mut original_size = 0;

    loop {
        let res = input_reader.read(&mut buff);

        if res.is_err() {
            break;
        }

        let amt = res.unwrap();

        debug!("AMT: {}", amt);

        if amt == 0 {
            break;
        }

        original_size += amt;

        let compressed_data = compress.compress(&buff[0..amt], 2).or_else(|e| { error!("Error compressing input"); Err(e) })?;

        debug!("PT: {}", compressed_data.len());

        // serialize the size of the block
        output_writer.write_u32::<BE>(compressed_data.len() as u32).expect("Error writing block size");

        // write out the compressed data
        output_writer.write_all(&compressed_data).or_else(|e| { error!("Error writing to output"); Err(e) })?;
    }

    if let Some(path) = size_file {
        let mut file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(path).or_else(|e| { error!("Error opening size info file"); Err(e) })?;

        file.write_all(format!("original={}\n", original_size).as_bytes())?;
    }

    Ok( () )
}

fn decompress(input_reader: &mut (dyn Read), output_writer: &mut (dyn Write)) -> Result<(), Box<dyn Error>> {
    let mut decompress = Decompressor::new();

    loop {
        let block_size = input_reader.read_u32::<BE>();

        debug!("BLOCK_SIZE: {:?}", block_size);

        // we only get an error when we've reached the end of the buffer
        if block_size.is_err() {
            break;
        }

        let block_size = block_size.unwrap();

        let mut buff = vec![0; block_size as usize];
        let res = input_reader.read_exact(&mut buff);

        if res.is_err() {
            break;
        }

        let plaintext = decompress.decompress(&buff, BLOCK_SIZE).or_else(|e| { error!("Error decompressing input"); Err(e) })?;

        output_writer.write_all(&plaintext).or_else(|e| { error!("Error writing to output"); Err(e) })?;
    }

    Ok( () )
}


fn main() -> Result<(), Box<dyn Error>> {
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
        .arg(Arg::with_name("compress")
            .conflicts_with("encrypt")
            .conflicts_with("password")
            .conflicts_with("salt")
            .short("c")
            .long("compress")
            .help("Only compress the input, NO ENCRYPTION"))
        .arg(Arg::with_name("size-info")
            .long("size-info")
            .conflicts_with("decrypt")  // cannot run when decrypting
            .value_name("FILE")
            .help("Generate a file with size information")
            .takes_value(true))
        .arg(Arg::with_name("v")
            .short("v")
            .multiple(true)
            .help("Sets the level of verbosity"))
        .get_matches();

    let verbosity = matches.occurrences_of("v");

    let log_level = match verbosity {
        0 => log::LevelFilter::Error,
        1 => log::LevelFilter::Info,
        2 => log::LevelFilter::Debug,
        _ => log::LevelFilter::Trace
    };

    fern::Dispatch::new()
        .format(|out, message, record| {
            out.finish(format_args!(
                "{}[{}][{}] {}",
                chrono::Local::now().format("[%Y-%m-%d][%H:%M:%S]"),
                record.target(),
                record.level(),
                message
            ))
        })
        .level(log_level)
        .chain(std::io::stderr())
        .apply().expect("Error configuring logger");

    let input = matches.value_of("input").unwrap_or("-");
    let output = matches.value_of("output").unwrap_or("-");
    let password = matches.value_of("password").or_else(|| { error!("Must supply a password!"); None }).unwrap();

    debug!("INPUT: {}", input);
    debug!("OUTPUT: {}", output);

    // construct the input reader from either STDIN or from the file
    let mut input_reader: Box<dyn BufRead> = if input == "-" {
        Box::new(BufReader::new(stdin()))
    } else {
        Box::new(BufReader::new(fs::OpenOptions::new()
            .read(true)
            .write(false)
            .create(false)
            .open(input).or_else(|e| { error!("Error opening input file"); Err(e) })?))
    };

    // construct the output writer from either STDOUT or from the file
    let mut output_writer: Box<dyn Write> = if output == "-" {
        Box::new(BufWriter::new(stdout()))
    } else {
        Box::new(BufWriter::new(fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(output).or_else(|e| { error!("Error opening output file"); Err(e) })?))
    };

    if matches.is_present("decrypt") {
        info!("Attempting to expand & decrypt: {}", input);

        let file_header = read_file_header(&mut input_reader)?;

        debug!("SALT: {}", file_header.salt);

        // check to see if we're decompressing only
        if file_header.salt == COMPRESS_STR &&
            file_header.nonce_seed == COMPRESS_STR.as_bytes().to_vec() &&
            file_header.comments[&"type".to_string()] == COMPRESS_STR {
            decompress(&mut input_reader, &mut output_writer)?;
        } else {
            let mut nonce_seed = [0; 8];

            nonce_seed.copy_from_slice(&file_header.nonce_seed);

            decrypt(&mut input_reader, &mut output_writer, password, &file_header.salt, nonce_seed)?;
        }
    } else if matches.is_present("compress") {
        info!("Attempting to ONLY compress: {}", input);

        compress(&mut input_reader, &mut output_writer, matches.value_of("size-info"))?;
    } else {
        info!("Attempting to encrypt: {}", input);

        let salt = matches.value_of("salt").or_else(|| { error!("Must supply salt!"); None }).unwrap();

        debug!("SALT: {}", salt);

        encrypt(&mut input_reader, &mut output_writer, password, salt, matches.value_of("size-info"))?;
    }

    Ok( () )
}

#[cfg(test)]
mod main_tests {
    use std::io::{Cursor};
    use ring::rand::{SystemRandom, SecureRandom};

    use std::sync::{Once};
    static LOGGER_INIT: Once = Once::new();


    fn encrypt_decrypt_test(buff_size: usize) {
        LOGGER_INIT.call_once(|| simple_logger::init().unwrap()); // this will panic on error

        let rand = SystemRandom::new();

        let mut input_buffer = vec![0; buff_size];

        rand.fill(&mut input_buffer).expect("Error reading random");

        let mut input_reader = Cursor::new(input_buffer);

        let mut encrypt_buffer = Vec::new();

        crate::encrypt(&mut input_reader, &mut encrypt_buffer, "password", "salt", None).expect("Error encrypting");

        let mut encrypt_reader = Cursor::new(encrypt_buffer);
        let mut plaintext_buffer = Vec::new();

        let file_header = crate::read_file_header(&mut encrypt_reader).expect("Error reading file header");

        let mut nonce_seed = [0; 8];

        nonce_seed.copy_from_slice(&file_header.nonce_seed);

        crate::decrypt(&mut encrypt_reader, &mut plaintext_buffer, "password", &file_header.salt, nonce_seed).expect("Error decrypting");

        assert_eq!(plaintext_buffer, input_reader.into_inner());
    }

    #[test] fn test_zero_block_encrypt_decrypt() { encrypt_decrypt_test(0); }
    #[test] fn test_small_encrypt_decrypt() { encrypt_decrypt_test(10); }
    #[test] fn test_single_block_encrypt_decrypt() { encrypt_decrypt_test(crate::BLOCK_SIZE); }
    #[test] fn test_two_blocks_encrypt_decrypt() { encrypt_decrypt_test(crate::BLOCK_SIZE * 2); }
    #[test] fn test_ten_blocks_encrypt_decrypt() { encrypt_decrypt_test(crate::BLOCK_SIZE * 10); }


    fn compress_decompress_test(buff_size: usize) {
        LOGGER_INIT.call_once(|| simple_logger::init().unwrap()); // this will panic on error
        let rand = SystemRandom::new();

        let mut input_buffer = vec![0; buff_size];

        rand.fill(&mut input_buffer).expect("Error reading random");

        let mut input_reader = Cursor::new(input_buffer);

        let mut compress_buffer = Vec::new();

        crate::compress(&mut input_reader, &mut compress_buffer, None).expect("Error compressing");

        let mut compress_reader = Cursor::new(compress_buffer);
        let mut plaintext_buffer = Vec::new();

        let file_header = crate::read_file_header(&mut compress_reader).expect("Error reading file header");

        assert_eq!(file_header.salt, crate::COMPRESS_STR);
        assert_eq!(file_header.nonce_seed, crate::COMPRESS_STR.as_bytes().to_vec());

        crate::decompress(&mut compress_reader, &mut plaintext_buffer).expect("Error decompressing");

        assert_eq!(plaintext_buffer, input_reader.into_inner());
    }

    #[test] fn test_zero_block_compress_decompress() { compress_decompress_test(0); }
    #[test] fn test_small_compress_decompress() { compress_decompress_test(10); }
    #[test] fn test_single_block_compress_decompress() { compress_decompress_test(crate::BLOCK_SIZE); }
    #[test] fn test_two_blocks_compress_decompress() { compress_decompress_test(crate::BLOCK_SIZE * 2); }
    #[test] fn test_ten_blocks_compress_decompress() { compress_decompress_test(crate::BLOCK_SIZE * 10); }

}