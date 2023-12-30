// Data input and output for the AES block ciphers are blocks
#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(non_upper_case_globals)]
#![allow(non_snake_case)]

use rand::Rng;

mod constants;
mod data;
mod utility;

use crate::constants::Nk;
use crate::data::Data;
use crate::utility::{key_expansion, cipher, inv_cipher};


pub fn gen_key() -> [u8; 4 * Nk as usize] {
    rand::thread_rng().gen::<[u8; 4 * Nk as usize]>()
}

pub fn encrypt(plain_text: &[u8], key: &[u8]) -> Vec<u8> {
    let key_schedule: Vec<u32> = key_expansion(key);
    let mut data: Data = Data::from_plain_text_bytes(plain_text);

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
