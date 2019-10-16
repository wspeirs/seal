use ring::pbkdf2::{derive, PBKDF2_HMAC_SHA512};
use ring::aead::{AES_256_GCM, NonceSequence, Nonce, BoundKey, UnboundKey, SealingKey, Aad};
use ring::error::Unspecified;

use byteorder::{ReadBytesExt, WriteBytesExt, BE};

use std::num::NonZeroU32;

#[derive(Debug)]
pub(crate) struct CountingNonceSequence {
    count: u32,     // low part of the nonce
    buff: [u8; 12]  // contains the whole buffer: seed || count
}

impl CountingNonceSequence {
    pub fn new(nonce_seed: &[u8; 8]) -> CountingNonceSequence {
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

        return Ok(Nonce::assume_unique_for_key(self.buff));
    }
}

///
/// Seals (encrypts) data block-by-block
///
pub struct Sealer {
    sealing_key: SealingKey<CountingNonceSequence>
}

impl Sealer {
    pub fn new(password: &str, salt: &[u8], nonce_seed: [u8; 8]) -> Sealer {
        let iterations = unsafe { NonZeroU32::new_unchecked(100) };
        let key_len = AES_256_GCM.key_len();
        let mut key = vec![0; key_len];

        // derive a key from a password
        derive(PBKDF2_HMAC_SHA512, iterations, &salt, password.as_bytes(), &mut key);

        // construct the UnboundKey from the derived key
        let unbound_key = UnboundKey::new(&AES_256_GCM, &key).expect("Error creating unbound key");

        // construct the NonceSequence
        let nonce_sequence = CountingNonceSequence::new(&nonce_seed);

        // create the SealingKey
        let sealing_key = SealingKey::new(unbound_key, nonce_sequence);

        Sealer {
            sealing_key
        }
    }

    pub fn seal(&mut self, block: Vec<u8>) -> Vec<u8> {
        let mut buff = block.clone();

        // resize our buffer to include the tag
        buff.resize(block.len() + AES_256_GCM.tag_len(), 0);

        self.sealing_key.seal_in_place_append_tag(Aad::empty(), &mut buff);

        buff
    }
}

#[cfg(test)]
mod tests {
    use crate::enc::CountingNonceSequence;
    use crate::ring::aead::NonceSequence;
    use crate::enc::Sealer;

    #[test]
    fn counting_nonce() {
        let mut cns = CountingNonceSequence::new(&[1,2,3,4,5,6,7,8]);

        cns.advance().unwrap();
        cns.advance().unwrap();

        println!("{:?}", cns);
    }

    #[test]
    fn encrypt_blocks() {
        let mut sealer = Sealer::new("my password", &[1,2,3,4,5,6,7,8,9,0], [1,2,3,4,5,6,7,8]);
        let block = "here is my block".as_bytes().to_vec();

        println!("{:?}", block);

        let res = sealer.seal(block);

        println!("{:?}", res);
    }
}

