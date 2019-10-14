extern crate libflate;
extern crate ring;

use std::io::{self, Read, BufReader, BufWriter, Cursor};
use std::io::prelude::*;
use std::fs::File;
use libflate::gzip;



fn main() {
    let mut stdin = BufReader::new(io::stdin());
    let mut stdout = BufWriter::new(io::stdout());
    let mut buff = Cursor::new(Vec::new());

    let mut encoder = gzip::Encoder::new(buff).unwrap();

    io::copy(&mut stdin, &mut encoder);
    let mut res = encoder.finish().into_result().unwrap();

    res.set_position(0);

    let mut decoder = gzip::Decoder::new(res).expect("Read GZIP header failed");

    io::copy(&mut decoder, &mut stdout);
}
