// Data input and output for the AES block ciphers are blocks
#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(non_upper_case_globals)]
#![allow(non_snake_case)]

use rand::Rng;
use bitvec::prelude::*;
use hex;

mod constants;
mod data;
mod utility;

use crate::constants::Nk;
use crate::data::Data;
use crate::utility::{
    key_expansion, 
    cipher, 
    inv_cipher, 
    byteslice_to_bitvec, 
    bitslice_to_bytevec, 
    ghash, 
    gctr, 
    inc, 
    msb, 
    aes_ecb_cipher,
};


pub fn gen_key() -> [u8; 4 * Nk as usize] {
    rand::thread_rng().gen::<[u8; 4 * Nk as usize]>()
}

pub fn encrypt(plaintext: &[u8], key: &[u8]) -> Vec<u8> {
    let key_schedule: Vec<u32> = key_expansion(key);
    let mut data: Data = Data::from_plaintext_bytes(plaintext);

    for i in 0..data.states.len() {
        cipher(&mut data.states[i], &key_schedule);
    }

    data.to_encrypted_bytes()
}

pub fn decrypt(cipher_text: &[u8], key: &[u8]) -> Vec<u8> {
    let key_schedule: Vec<u32> = key_expansion(key);
    let mut data: Data = Data::from_cipher_text_bytes(cipher_text);

    for i in 0..data.states.len() {
        inv_cipher(&mut data.states[i], &key_schedule);
    }

    data.to_decrypted_bytes()
}

pub fn encrypt_gcm(plaintext: &[u8], iv: &[u8], aad: &[u8], key: &[u8], tag_len: usize) -> (Vec<u8>, Vec<u8>) {
    // Generate the hash subkey for the GHASH function by applying block cipher to zero block and convert to bitvec
    let zero_block: Vec<u8> = vec![0_u8; 16]; // 128-bit zero block
    let hash_subkey: BitVec = byteslice_to_bitvec(&aes_ecb_cipher(&zero_block, &key));

    // Define pre-counter block
    let precounter_block: BitVec;

    if iv.len() == 12 { // Is the bit length of IV is 96?
        println!("12");
        // Create bitvector out of the IV
        let mut bv1: BitVec = byteslice_to_bitvec(iv);

        // Create 31-bit zero bitvector concatenated with 1 true bit 
        let mut bv2: BitVec = bitvec![0; 32];
        bv2.set(31, true);

        // Concatenate the two bitvectors into one 128-bit bitvec
        bv1.extend(bv2);

        // Convert bitvec into vector of bytes and set j_block equal to this
        precounter_block = bv1;
    } else {
        println!("not 12");
        // s represents the number of padding bits that when added to IV creates a bitvec with length a multiple of 128
        let num_pad_bits = (128 - ((iv.len() * 8) % 128)) % 128;

        // Create bitvector out of IV
        let mut bv1: BitVec = byteslice_to_bitvec(iv);

        // Create padding bitvec
        let bv2: BitVec = bitvec![0; num_pad_bits + 64];

        // Convert length of IV (in bits) to byte vector
        let bitlen_vec = (iv.len() as u64).to_be_bytes().to_vec();

        // Convert bitlen_vec into bitvec
        let bv3: BitVec = byteslice_to_bitvec(&bitlen_vec);

        // Concatenate all three bitvectors
        bv1.extend(bv2);
        bv1.extend(bv3);

        // Set precounter_block equal to the GHASH of the padded IV with the hash_subkey - Result is multiple of 128 (bits)
        precounter_block = ghash(&bv1, &hash_subkey);
    }

    // The 32-bit increment function is applied to the pre-counter block to produce the initial
    // counter block for an invocation of the GCTR function on the plaintext
    let iniitial_counter_block = inc(&precounter_block, 32);

    // Invoke the GCTR function to get the ciphertext
    let ciphertext = gctr(&iniitial_counter_block, &byteslice_to_bitvec(&plaintext), key);

    // Convert AAD to a bitvec
    let mut aad_bits: BitVec = byteslice_to_bitvec(aad);

    // Compute the minimum number of '0' bits, possibly none, so that the bit lengths of the resulting strings are multiple of 128
    let cipher_padsize = (128 - (ciphertext.len() % 128)) % 128;
    let aad_padsize = (128 - (aad_bits.len() % 128)) % 128;

    // Get the lengths of AAD and the ciphertext and convert each length into a bitvec
    let aad_len = (aad_bits.len() as u64).to_be_bytes().to_vec();
    let cipher_len = (ciphertext.len() as u64).to_be_bytes().to_vec();
    let c_len = byteslice_to_bitvec(&cipher_len);
    let a_len = byteslice_to_bitvec(&aad_len);

    // Construct new bitvec out of the AAD and ciphertext as well as paddings and lengths
    let aad_pad = bitvec![0; aad_padsize];
    let cipher_pad = bitvec![0; cipher_padsize];

    aad_bits.extend(aad_pad);
    aad_bits.extend(ciphertext.clone());
    aad_bits.extend(cipher_pad);
    aad_bits.extend(a_len);
    aad_bits.extend(c_len);

    // Compute the hash of this new bitvec using the hash subkey
    let s = ghash(&aad_bits, &hash_subkey);

    // Encrypt the GHASH output block using GCTR with the pre-counter block and truncate to the tag length
    let auth_tag = msb(&gctr(&precounter_block, &s, key), tag_len);

    // Convert both the ciphertext and the authentication tag back into Vec<u8>
    let ciphertext_bytes = bitslice_to_bytevec(&ciphertext);
    let auth_tag_bytes = bitslice_to_bytevec(&auth_tag);

    // Return the ciphertext and auth tag
    (ciphertext_bytes, auth_tag_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_gcm() {
        let key_str = "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308";
        let iv_str = "cafebabefacedbaddecaf888";
        let plaintext_str = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39";
        let aad_str = "feedfacedeadbeeffeedfacedeadbeefabaddad2";

        let key: Vec<u8> = hex::decode(key_str).expect("failed");
        let iv: Vec<u8> = hex::decode(iv_str).expect("failed");
        let plaintext: Vec<u8> = hex::decode(plaintext_str).expect("failed");
        let aad: Vec<u8> = hex::decode(aad_str).expect("failed");

        let (c, t) = encrypt_gcm(&plaintext, &iv, &aad, &key, 128);

        let target_c_str = "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662";
        let target_t_str = "76fc6ece0f4e1768cddf8853bb2d551b";

        let target_c: Vec<u8> = hex::decode(target_c_str).expect("failed");
        let target_t: Vec<u8> = hex::decode(target_t_str).expect("failed");

        assert_eq!(c, target_c);
        assert_eq!(t, target_t);
    }
}
