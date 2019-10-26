use ring::pbkdf2::{derive, PBKDF2_HMAC_SHA512};
use ring::aead::{AES_256_GCM, NonceSequence, Nonce, BoundKey, UnboundKey, SealingKey, Aad, OpeningKey};
use ring::error::Unspecified;

use byteorder::{WriteBytesExt, BE};

use std::num::NonZeroU32;
use std::error::Error;

#[derive(Debug)]
pub(crate) struct CountingNonceSequence {
    count: u32,     // low part of the nonce
    buff: [u8; 12]  // contains the whole buffer: seed || count
}

impl CountingNonceSequence {
    pub fn new(nonce_seed: [u8; 8]) -> CountingNonceSequence {
        let mut buff = [0 as u8; 12];

        buff[..8].copy_from_slice(&nonce_seed[..]);

        CountingNonceSequence {
            count: 0,
            buff: buff
        }
    }
}

impl NonceSequence for CountingNonceSequence {
    fn advance(&mut self) -> Result<Nonce, Unspecified> {
        if self.count == std::u32::MAX {
            return Err(Unspecified);
        }

        self.count += 1; // increment our count

        let mut tmp = Vec::new();

        tmp.write_u32::<BE>(self.count).expect("Error serializing counter");

        self.buff[8..].copy_from_slice(&tmp);

        Ok(Nonce::assume_unique_for_key(self.buff))
    }
}

///
/// Seals (encrypts) data block-by-block
///
pub struct Sealer {
    sealing_key: SealingKey<CountingNonceSequence>
}

impl Sealer {
    pub fn new(password: &str, salt: &[u8], nonce_seed: [u8; 8]) -> Result<Sealer, Box<dyn Error>> {
        let iterations = unsafe { NonZeroU32::new_unchecked(100) };
        let key_len = AES_256_GCM.key_len();
        let mut key = vec![0; key_len];

        // derive a key from a password
        derive(PBKDF2_HMAC_SHA512, iterations, &salt, password.as_bytes(), &mut key);

        // construct the UnboundKey from the derived key
        let unbound_key = UnboundKey::new(&AES_256_GCM, &key).or_else(|e| { error!("Error creating unbound key"); Err(e) })?;

        // construct the NonceSequence
        let nonce_sequence = CountingNonceSequence::new(nonce_seed);

        // create the SealingKey
        let sealing_key = SealingKey::new(unbound_key, nonce_sequence);

        Ok(Sealer {
            sealing_key
        })
    }

    pub fn seal(&mut self, block: Vec<u8>) -> Vec<u8> {
        let block_len = block.len() + AES_256_GCM.tag_len();
        let mut buff = Vec::with_capacity(4 + block_len);

        debug!("BLOCK_LEN: {}", block_len);

        // serialize the size of the block
        buff.write_u32::<BE>(block_len as u32).expect("Error writing block size");

        // resize our buffer to include space for the tag
        buff.resize(4 + block_len, 0);

        // copy in-place the block
        buff[4..block.len()+4].copy_from_slice(&block);

        // encrypt and tag the block
        let res = self.sealing_key.seal_in_place_separate_tag(Aad::empty(), &mut buff[4..block.len()+4]).expect("Error encrypting");

        buff[block.len()+4..].copy_from_slice(res.as_ref());

        buff
    }
}

///
/// Opens (decrypts) block-by-block
///
pub struct Opener {
    opening_key: OpeningKey<CountingNonceSequence>
}

impl Opener {
    pub fn new(password: &str, salt: &[u8], nonce_seed: [u8; 8]) -> Result<Opener, Box<dyn Error>> {
        let iterations = unsafe { NonZeroU32::new_unchecked(100) };
        let key_len = AES_256_GCM.key_len();
        let mut key = vec![0; key_len];

        // derive a key from a password
        derive(PBKDF2_HMAC_SHA512, iterations, &salt, password.as_bytes(), &mut key);

        // construct the UnboundKey from the derived key
        let unbound_key = UnboundKey::new(&AES_256_GCM, &key).expect("Error creating unbound key");

        // construct the NonceSequence
        let nonce_sequence = CountingNonceSequence::new(nonce_seed);

        // create the OpeningKey
        let opening_key = OpeningKey::new(unbound_key, nonce_sequence);

        Ok(Opener {
            opening_key: opening_key
        })
    }

    pub fn open(&mut self, mut block: Vec<u8>) -> Vec<u8> {
        let res = self.opening_key.open_within(Aad::empty(), &mut block, 0..).expect("Error opening");

        res.to_vec()
    }
}


#[cfg(test)]
mod tests {
    use crate::enc::CountingNonceSequence;
    use crate::ring::aead::NonceSequence;
    use crate::enc::{Sealer, Opener};

    #[test]
    fn counting_nonce() {
        let mut cns = CountingNonceSequence::new([1,2,3,4,5,6,7,8]);

        cns.advance().unwrap();
        cns.advance().unwrap();

        eprintln!("{:?}", cns);
    }

    #[test]
    fn encrypt_blocks() {
        let mut sealer = Sealer::new("my password", &[1,2,3,4,5,6,7,8,9,0], [1,2,3,4,5,6,7,8]).unwrap();
        let block = "here is my block".as_bytes().to_vec();

        eprintln!("{:?}", block);

        let res = sealer.seal(block);

        eprintln!("{:?}", res);
    }

    #[test]
    fn encrypt_decrypt() {
        let mut sealer = Sealer::new("my password", &[1,2,3,4,5,6,7,8,9,0], [1,2,3,4,5,6,7,8]).unwrap();
        let mut opener = Opener::new("my password", &[1,2,3,4,5,6,7,8,9,0], [1,2,3,4,5,6,7,8]).unwrap();

        let orig_text = "here is my block".as_bytes().to_vec();
        let cipher_text = sealer.seal(orig_text.clone());
        let cipher_text = cipher_text[4..].to_vec();
        let plain_text = opener.open(cipher_text);
        assert_eq!(orig_text, plain_text);

        let orig_text = "this is another block".as_bytes().to_vec();
        let cipher_text = sealer.seal(orig_text.clone());
        let cipher_text = cipher_text[4..].to_vec();
        let plain_text = opener.open(cipher_text);
        assert_eq!(orig_text, plain_text);
    }
}

