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

pub fn encrypt_ecb(plaintext: &[u8], key: &[u8]) -> Vec<u8> {
    let key_schedule: Vec<u32> = key_expansion(key);
    let mut data: Data = Data::from_plaintext_bytes(plaintext);

    for i in 0..data.states.len() {
        cipher(&mut data.states[i], &key_schedule);
    }

    data.to_encrypted_bytes()
}

pub fn decrypt_ecb(cipher_text: &[u8], key: &[u8]) -> Vec<u8> {
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
        // Create bitvector out of IV
        let mut iv_bits: BitVec = byteslice_to_bitvec(iv);

        // This represents the number of padding bits that when added to IV creates a bitvec with length a multiple of 128
        let blocksize_multiple_pad_len = (128 - (iv_bits.len() % 128)) % 128;

        // Create the first pad based on blocksize_multiple_pad_len
        let zeros_pad: BitVec = bitvec![0; blocksize_multiple_pad_len + 64];

        // NOTE: We add the extra 64 since in the next step we will be adding another 64-bits for the encoded length
        //       This additional 64 bits assures that the total length is still a multiple of 128.

        // Convert 64-bit length of IV to byte vector
        let bitlen_vec = (iv_bits.len() as u64).to_be_bytes().to_vec();

        // Convert bitlen_vec into bitvec
        let length_pad: BitVec = byteslice_to_bitvec(&bitlen_vec);

        // Concatenate all three bitvectors
        iv_bits.extend(zeros_pad);
        iv_bits.extend(length_pad);

        // Set precounter_block equal to the GHASH of the padded IV with the hash_subkey - Result has same length as input
        precounter_block = ghash(&iv_bits, &hash_subkey);
    }

    // The 32-bit increment function is applied to the pre-counter block to produce the initial
    // counter block for an invocation of the GCTR function on the plaintext
    let iniitial_counter_block = inc(&precounter_block, 32);

    // Invoke the GCTR function to get the ciphertext
    let ciphertext = gctr(&iniitial_counter_block, &byteslice_to_bitvec(&plaintext), key);

    // Convert AAD to a bitvec
    let mut aad_bits: BitVec = byteslice_to_bitvec(aad);

    // Compute the minimum number of '0' bits, possibly none, so that the bit lengths of the resulting strings are multiples of 128
    let ciphertext_pad_len = (128 - (ciphertext.len() % 128)) % 128;
    let aad_pad_len = (128 - (aad_bits.len() % 128)) % 128;

    // Get the 64-bit lengths of AAD and the ciphertext and convert to BE byte vector
    let aad_len_vec = (aad_bits.len() as u64).to_be_bytes().to_vec();
    let ciphertext_len_vec = (ciphertext.len() as u64).to_be_bytes().to_vec();

    // Convert length byte vectors into bitvectors
    let ciphertext_len_pad = byteslice_to_bitvec(&ciphertext_len_vec);
    let aad_len_pad = byteslice_to_bitvec(&aad_len_vec);

    // Construct new bitvec out of the AAD and ciphertext as well as zero pads and length pads
    let aad_zeros_pad = bitvec![0; aad_pad_len];
    let ciphertext_zeros_pad = bitvec![0; ciphertext_pad_len];

    // Append each bitvec to aad_bits
    aad_bits.extend(aad_zeros_pad);
    aad_bits.extend(ciphertext.clone());
    aad_bits.extend(ciphertext_zeros_pad);
    aad_bits.extend(aad_len_pad);
    aad_bits.extend(ciphertext_len_pad);

    // Compute the hash of this extended bitvec using the hash subkey
    let s = ghash(&aad_bits, &hash_subkey);

    // Encrypt the GHASH output block using GCTR with the pre-counter block and truncate to the tag length
    let auth_tag = msb(&gctr(&precounter_block, &s, key), tag_len);

    // Convert both the ciphertext and the authentication tag back into Vec<u8>
    let ciphertext_bytes = bitslice_to_bytevec(&ciphertext);
    let auth_tag_bytes = bitslice_to_bytevec(&auth_tag);

    // Return the ciphertext and auth tag
    (ciphertext_bytes, auth_tag_bytes)
}

pub fn decrypt_gcm(ciphertext: &[u8], iv: &[u8], aad: &[u8], auth_tag: &[u8], key: &[u8]) -> (Vec<u8>, bool) {
    // TODO: Validate size of inputs

    // Generate the hash subkey for the GHASH function by applying block cipher to zero block and convert to bitvec
    let zero_block: Vec<u8> = vec![0_u8; 16]; // 128-bit zero block
    let hash_subkey: BitVec = byteslice_to_bitvec(&aes_ecb_cipher(&zero_block, &key));

    // Define pre-counter block
    let precounter_block: BitVec;

    if iv.len() == 12 { // Is the bit length of IV is 96?
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
        // Create bitvector out of IV
        let mut iv_bits: BitVec = byteslice_to_bitvec(iv);

        // This represents the number of padding bits that when added to IV creates a bitvec with length a multiple of 128
        let blocksize_multiple_pad_len = (128 - (iv_bits.len() % 128)) % 128;

        // Create the first pad based on blocksize_multiple_pad_len
        let zeros_pad: BitVec = bitvec![0; blocksize_multiple_pad_len + 64];

        // NOTE: We add the extra 64 since in the next step we will be adding another 64-bits for the encoded length
        //       This additional 64 bits assures that the total length is still a multiple of 128.

        // Convert 64-bit length of IV to byte vector
        let bitlen_vec = (iv_bits.len() as u64).to_be_bytes().to_vec();

        // Convert bitlen_vec into bitvec
        let length_pad: BitVec = byteslice_to_bitvec(&bitlen_vec);

        // Concatenate all three bitvectors
        iv_bits.extend(zeros_pad);
        iv_bits.extend(length_pad);

        // Set precounter_block equal to the GHASH of the padded IV with the hash_subkey - Result has same length as input
        precounter_block = ghash(&iv_bits, &hash_subkey);
    }

    // Convert ciphertext to bitvector
    let ciphertext_bits: BitVec = byteslice_to_bitvec(&ciphertext);

    // The 32-bit increment function is applied to the pre-counter block to produce the initial
    // counter block for an invocation of the GCTR function on the ciphertext
    let iniitial_counter_block = inc(&precounter_block, 32);

    // Invoke the GCTR function to get the ciphertext
    let plaintext = gctr(&iniitial_counter_block, &ciphertext_bits, key);

    // Convert AAD to a bitvec
    let mut aad_bits: BitVec = byteslice_to_bitvec(aad);

    // Compute the minimum number of '0' bits, possibly none, so that the bit lengths of the resulting strings are multiples of 128
    let ciphertext_pad_len = (128 - (ciphertext_bits.len() % 128)) % 128;
    let aad_pad_len = (128 - (aad_bits.len() % 128)) % 128;

    // Get the 64-bit lengths of AAD and the ciphertext and convert to BE byte vector
    let aad_len_vec = (aad_bits.len() as u64).to_be_bytes().to_vec();
    let ciphertext_len_vec = (ciphertext_bits.len() as u64).to_be_bytes().to_vec();

    // Convert length byte vectors into bitvectors
    let ciphertext_len_pad = byteslice_to_bitvec(&ciphertext_len_vec);
    let aad_len_pad = byteslice_to_bitvec(&aad_len_vec);

    // Construct new bitvec out of the AAD and ciphertext as well as zero pads and length pads
    let aad_zeros_pad = bitvec![0; aad_pad_len];
    let ciphertext_zeros_pad = bitvec![0; ciphertext_pad_len];

    // Append each bitvec to aad_bits
    aad_bits.extend(aad_zeros_pad);
    aad_bits.extend(ciphertext_bits.clone());
    aad_bits.extend(ciphertext_zeros_pad);
    aad_bits.extend(aad_len_pad);
    aad_bits.extend(ciphertext_len_pad);

    // Compute the hash of this extended bitvec using the hash subkey
    let s = ghash(&aad_bits, &hash_subkey);

    // Extract the computed authentication tag by truncating the output of GCTR with the MSB function
    let tag_len = auth_tag.len() * 8;
    let computed_auth_tag = msb(&gctr(&precounter_block, &s, key), tag_len);

    // Convert computed_auth_tag back to byte vector and compare
    let computed_auth_tag_bytes = bitslice_to_bytevec(&computed_auth_tag);
    if computed_auth_tag_bytes != auth_tag {
        println!("Error: Invalid Authentication Tag.");
        return (Vec::new(), false);
    }

    // Convert the plaintext to a byte vector and return
    let plaintext_bytes = bitslice_to_bytevec(&plaintext);

    (plaintext_bytes, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test Vectors taken from: https://github.com/google/boringssl/blob/master/crypto/cipher_extra/test/cipher_tests.txt
    //                          https://luca-giuzzi.unibs.it/corsi/Support/papers-cryptography/gcm-spec.pdf

    #[test]
    fn test_encrypt_gcm1() {
        let key_str = "0000000000000000000000000000000000000000000000000000000000000000";
        let iv_str = "000000000000000000000000";
        let plaintext_str = "00000000000000000000000000000000";

        let key: Vec<u8> = hex::decode(key_str).unwrap();
        let iv: Vec<u8> = hex::decode(iv_str).unwrap();
        let plaintext: Vec<u8> = hex::decode(plaintext_str).unwrap();
        let aad: Vec<u8> = Vec::new();

        let (ciphertext, auth_tag) = encrypt_gcm(&plaintext, &iv, &aad, &key, 128);

        let target_ciphertext_str = "cea7403d4d606b6e074ec5d3baf39d18";
        let target_auth_tag_str = "d0d1c8a799996bf0265b98b5d48ab919";

        let target_ciphertext: Vec<u8> = hex::decode(target_ciphertext_str).unwrap();
        let target_auth_tag: Vec<u8> = hex::decode(target_auth_tag_str).unwrap();

        assert_eq!(ciphertext, target_ciphertext);
        assert_eq!(auth_tag, target_auth_tag);
    }

    #[test]
    fn test_encrypt_gcm2() {
        let key_str = "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308";
        let iv_str = "cafebabefacedbaddecaf888";
        let plaintext_str = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39";
        let aad_str = "feedfacedeadbeeffeedfacedeadbeefabaddad2";

        let key: Vec<u8> = hex::decode(key_str).unwrap();
        let iv: Vec<u8> = hex::decode(iv_str).unwrap();
        let plaintext: Vec<u8> = hex::decode(plaintext_str).unwrap();
        let aad: Vec<u8> = hex::decode(aad_str).unwrap();

        let (ciphertext, auth_tag) = encrypt_gcm(&plaintext, &iv, &aad, &key, 128);

        let target_ciphertext_str = "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662";
        let target_auth_tag_str = "76fc6ece0f4e1768cddf8853bb2d551b";

        let target_ciphertext: Vec<u8> = hex::decode(target_ciphertext_str).unwrap();
        let target_auth_tag: Vec<u8> = hex::decode(target_auth_tag_str).unwrap();

        assert_eq!(ciphertext, target_ciphertext);
        assert_eq!(auth_tag, target_auth_tag);
    }

    #[test]
    fn test_decrypt_gcm1() {
        let key_str = "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308";
        let ciphertext_str = "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662";
        let iv_str = "cafebabefacedbaddecaf888";
        let aad_str = "feedfacedeadbeeffeedfacedeadbeefabaddad2";
        let auth_tag_str = "76fc6ece0f4e1768cddf8853bb2d551b";

        let key: Vec<u8> = hex::decode(key_str).unwrap();
        let iv: Vec<u8> = hex::decode(iv_str).unwrap();
        let ciphertext: Vec<u8> = hex::decode(ciphertext_str).unwrap();
        let aad: Vec<u8> = hex::decode(aad_str).unwrap();
        let auth_tag: Vec<u8> = hex::decode(auth_tag_str).unwrap();

        let (plaintext, result) = decrypt_gcm(&ciphertext, &iv, &aad, &auth_tag, &key);

        let target_plaintext_str = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39";
        let target_plaintext: Vec<u8> = hex::decode(target_plaintext_str).unwrap();

        assert_eq!(plaintext, target_plaintext);
        assert_eq!(result, true);
    }

    #[test]
    fn test_decrypt_gcm2() {
        let key_str = "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308";
        let ciphertext_str = "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662";
        let iv_str = "cafebabefacedbaddecaf888";
        let aad_str = "feedfacedeadbeeffeedfacedeadbeefabaddad2";
        let auth_tag_str = "76fc6ecf0f4e1768cddf8853bb2d551b";

        let key: Vec<u8> = hex::decode(key_str).unwrap();
        let iv: Vec<u8> = hex::decode(iv_str).unwrap();
        let ciphertext: Vec<u8> = hex::decode(ciphertext_str).unwrap();
        let aad: Vec<u8> = hex::decode(aad_str).unwrap();
        let auth_tag: Vec<u8> = hex::decode(auth_tag_str).unwrap();

        let (plaintext, result) = decrypt_gcm(&ciphertext, &iv, &aad, &auth_tag, &key);

        let target_plaintext_str = "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39";
        let target_plaintext: Vec<u8> = hex::decode(target_plaintext_str).unwrap();

        assert_eq!(result, false);
    }     
}
