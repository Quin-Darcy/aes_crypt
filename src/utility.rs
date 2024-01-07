use std::ops::BitXorAssign;

use bitvec::prelude::*;

use crate::constants::{
    BINS,
    GLOBAL_PRODUCT_CACHE,
    XPOW_PRODS,
    SBOX,
    INV_SBOX,
    Nk,
    RCON,
};


fn gcd(a: usize, b: usize) -> usize {
    if b == 0 {
        return a;
    } else {
        return gcd(b, a%b);
    }    
}

pub fn lcm(a: usize, b: usize) -> usize {
    (a / gcd(a, b)) * b        
}

pub fn least_multiple_greater_than(blocksize: usize, num_bytes: usize) -> usize {
    if blocksize <= 0 {
        panic!("a must be greater than 0");
    }
    let quotient = num_bytes / blocksize;
    let remainder = num_bytes % blocksize;
    if remainder == 0 {
        blocksize * (quotient + 1)
    } else {
        blocksize * (quotient + 1)
    }
}


fn dot(w1: [u8; 4], w2: [u8; 4]) -> u8 {
    w1.iter().zip(w2.iter()).fold(0, |acc, (&a, &b)| acc ^ prod(a, b))
}

fn prod(b1: u8, b2: u8) -> u8 {
    let bin: [u8; 8] = BINS[b1 as usize];
    let mut mult_val: u8;
    let mut product: u8 = 0;

    unsafe{
        if GLOBAL_PRODUCT_CACHE[b1 as usize][b2 as usize] != 0 {
            product = GLOBAL_PRODUCT_CACHE[b1 as usize][b2 as usize];
        } else {
            /*
             | b1 * b2 = (a7x^7+a6x^6+d5x^5+a4x^4+a3x^3+a2x^2+a1x^1+a0x^0) * b2
             |         = (a7x^7 * b2) + (a6x^6 * b2) + ... + (a0x^0 * b2)
             |         = XPOW_PROD[7][b2] + XPOW_PROD[6][b2] + ... + XPOW_PROD[0][b2]
             |         = XPOW_PROD[7][b2] ^ ... ^ XPOW_PROD[0][b2]
             */ 
            let temp: u8 = b1;
            for i in 0..8 {
                if bin[i] == 1 {
                    mult_val = XPOW_PRODS[8-i-1][b2 as usize];
                    product = product ^ mult_val;
                }
            }
            GLOBAL_PRODUCT_CACHE[temp as usize][b2 as usize] = product;
            GLOBAL_PRODUCT_CACHE[b2 as usize][temp as usize] = product;
        }
        product
    }
}

fn rot_word(w: u32) -> u32 {
    let bytes: [u8; 4] = w.to_be_bytes();
    return u32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[0]]);
}

fn sub_word(w: u32) -> u32 {
    let bytes: [u8; 4] = w.to_be_bytes();
    let mut sub_bytes: [u8; 4] = [0_u8; 4];

    for i in 0..4 {
        sub_bytes[i] = SBOX[bytes[i] as usize];
    }
    return u32::from_be_bytes(sub_bytes);
}

fn sub_bytes(state: &mut [[u8; 4]; 4]) {
    for i in 0..4 {
        for j in 0..4 {
            state[i][j] = SBOX[state[i][j] as usize];
        }
    } 
}

fn inv_sub_bytes(state: &mut [[u8; 4]; 4]) {
    for i in 0..4 {
        for j in 0..4 {
            state[i][j] = INV_SBOX[state[i][j] as usize];
        }
    }
}

fn shift_rows(state: &mut [[u8; 4]; 4]) {
    let mut new_state: [[u8; 4]; 4] = [[0_u8; 4]; 4];

    for i in 0..4 {
        for j in 0..4 {
            new_state[i][j] = state[i][(i+j)%4];
        }
    }
    *state = new_state;
}

fn inv_shift_rows(state: &mut [[u8; 4]; 4]) {
    let mut new_state: [[u8; 4]; 4] = [[0_u8; 4]; 4];

    for i in 0..4 {
        for j in 0..4 { 
            new_state[i][j] = state[i][(3*i+j)%4];
        }
    }
    *state = new_state;
}

fn mix_columns(state: &mut [[u8; 4]; 4]) {
    let state_copy: [[u8; 4]; 4] = (*state).clone();
    let mat: [[u8; 4]; 4] = [[0x02, 0x03, 0x01, 0x01],
                             [0x01, 0x02, 0x03, 0x01],
                             [0x01, 0x01, 0x02, 0x03],
                             [0x03, 0x01, 0x01, 0x02]];
    
    let mut c: [u8; 4];
    for i in 0..4 {
        c = [state_copy[0][i], state_copy[1][i], state_copy[2][i], state_copy[3][i]];
        for j in 0..4 {
            state[j][i] = dot(mat[j], c); 
        }
    }
}

fn inv_mix_columns(state: &mut [[u8; 4]; 4]) {
    let state_copy: [[u8; 4]; 4] = (*state).clone();
    let mat: [[u8; 4]; 4] = [[0x0e, 0x0b, 0x0d, 0x09],
                              [0x09, 0x0e, 0x0b, 0x0d],
                              [0x0d, 0x09, 0x0e, 0x0b],
                              [0x0b, 0x0d, 0x09, 0x0e]];

    let mut c: [u8; 4];
    for i in 0..4 {
        c = [state_copy[0][i], state_copy[1][i], state_copy[2][i], state_copy[3][i]];
        for j in 0..4{
            state[j][i] = dot(mat[j], c);
        }
    }
}

fn add_roundkey(state: &mut [[u8; 4]; 4], roundkeys: [u32; 4]) {
    let mut col_0: u32 = u32::from_be_bytes([state[0][0], state[1][0], state[2][0], state[3][0]]);
    let mut col_1: u32 = u32::from_be_bytes([state[0][1], state[1][1], state[2][1], state[3][1]]);
    let mut col_2: u32 = u32::from_be_bytes([state[0][2], state[1][2], state[2][2], state[3][2]]);
    let mut col_3: u32 = u32::from_be_bytes([state[0][3], state[1][3], state[2][3], state[3][3]]);

    col_0 = col_0 ^ roundkeys[0];
    col_1 = col_1 ^ roundkeys[1];
    col_2 = col_2 ^ roundkeys[2];
    col_3 = col_3 ^ roundkeys[3];

    let bytes_0: [u8; 4] = col_0.to_be_bytes();
    let bytes_1: [u8; 4] = col_1.to_be_bytes();
    let bytes_2: [u8; 4] = col_2.to_be_bytes();
    let bytes_3: [u8; 4] = col_3.to_be_bytes();

    *state = [[bytes_0[0], bytes_1[0], bytes_2[0], bytes_3[0]],
              [bytes_0[1], bytes_1[1], bytes_2[1], bytes_3[1]],
              [bytes_0[2], bytes_1[2], bytes_2[2], bytes_3[2]],
              [bytes_0[3], bytes_1[3], bytes_2[3], bytes_3[3]]];
}

pub fn key_expansion(key: &[u8]) -> Vec<u32> {
    let mut Nr: u32 = 10;
    if Nk == 4 {
        Nr = 10;
    } else if Nk == 6 {
        Nr = 12;
    } else if Nk == 8 {
        Nr = 14;
    }

    let mut i: u32 = 0;
    let mut key_word: u32;
    let mut w: Vec<u32> = Vec::new();
    while i <= Nk-1 {
        key_word = u32::from_be_bytes([key[(4*i) as usize], key[(4*i+1) as usize],
                                       key[(4*i+2) as usize], key[(4*i+3) as usize]]);
        w.push(key_word);
        i += 1;
    }

    let mut temp: u32;
    while i <= 4*Nr+3 {
        temp = w[(i-1) as usize];
        if i % Nk == 0 {
            temp = sub_word(rot_word(temp)) ^ RCON[(i/Nk-1) as usize];
        } else if Nk > 6 && i % Nk == 4 {
            temp = sub_word(temp);
        }
        w.push(w[(i-Nk) as usize]^temp);
        i += 1;
    }
    return w;
}

pub fn cipher(state: &mut [[u8; 4]; 4], w: &Vec<u32>) {
    let mut Nr: u32 = 10;
    if Nk == 4 {
        Nr = 10;
    } else if Nk == 6 {
        Nr = 12;
    } else if Nk == 8 {
        Nr = 14;
    }
    
    let mut roundkey: [u32; 4] = [w[0], w[1], w[2], w[3]];
    add_roundkey(state, roundkey);
    for i in 1..Nr {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        
        roundkey = [w[(4*i) as usize], w[(4*i+1) as usize], 
                     w[(4*i+2) as usize], w[(4*i+3) as usize]];

        add_roundkey(state, roundkey);
    }
    sub_bytes(state);
    shift_rows(state);

    roundkey = [w[(4*Nr) as usize], w[(4*Nr+1) as usize], 
                 w[(4*Nr+2) as usize], w[(4*Nr+3) as usize]];
    
    add_roundkey(state, roundkey);
}

pub fn inv_cipher(state: &mut [[u8; 4]; 4], w: &Vec<u32>) {
    let mut Nr: u32 = 10;
    if Nk == 4 {
        Nr = 10;
    } else if Nk == 6 {
        Nr = 12;
    } else if Nk == 8 {
        Nr = 14;
    }

    let mut roundkey: [u32; 4] = [w[(4*Nr) as usize], w[(4*Nr+1) as usize], 
                                   w[(4*Nr+2) as usize], w[(4*Nr+3) as usize]];
    add_roundkey(state, roundkey);
    for i in (1..Nr).rev() {
        inv_shift_rows(state);
        inv_sub_bytes(state);
        
        roundkey = [w[(4*i) as usize], w[(4*i+1) as usize], 
                     w[(4*i+2) as usize], w[(4*i+3) as usize]];

        add_roundkey(state, roundkey);
        inv_mix_columns(state);
    }
    inv_shift_rows(state);
    inv_sub_bytes(state);
    roundkey = [w[0], w[1], w[2], w[3]];
    add_roundkey(state, roundkey);
}

// This converts the byte_slice into one bitvec
pub fn byteslice_to_bitvec(byte_slice: &[u8]) -> BitVec {
    let num_bits = byte_slice.len() * 8;
    let mut bv: BitVec = BitVec::with_capacity(num_bits);

    for &byte in byte_slice {
        for i in 0..8 {
            if byte & (1 << (7 - i)) != 0 {
                bv.push(true);
            } else {
                bv.push(false);
            }
        }
    }

    bv
}

// This converts a bitslice to a bytevec
pub fn bitslice_to_bytevec(bitslice: &BitVec) -> Vec<u8> {
    let num_bytes = bitslice.len() / 8;
    let mut bytevec: Vec<u8> = Vec::with_capacity(num_bytes);

    for chunk in bitslice.chunks(8) {
        let mut byte = 0_u8;

        for (i, bit) in chunk.iter().enumerate() {
            if *bit {
                byte |= 1 << (7 - i);
            }
        }
        bytevec.push(byte);
    }

    bytevec
}

// Returns the least significant bits
fn lsb(bitslice: &BitVec, num_bits: usize) -> BitVec {
    // Ensure num_bits is not greater than the length of the bit vector.
    let len = bitslice.len();
    let num_bits = num_bits.min(len);

    // Calculate the start index for slicing.
    let start = if len > num_bits { len - num_bits } else { 0 };

    // Slice the BitVec from the calculated start index to the end.
    bitslice[start..].to_bitvec()
}

// Returns the most significant bits
pub fn msb(bitslice: &BitVec, num_bits: usize) -> BitVec {
    // Ensure num_bits is not greater than the length of the bit vector.
    let num_bits = num_bits.min(bitslice.len());

    // Slice the BitVec from the beginning to the desired length.
    bitslice[..num_bits].to_bitvec()
}

pub fn inc(bits: &BitVec, s: usize) -> BitVec {
    let len = bits.len();
    if s > len {
        println!("[{}] Error: Invalid value for s.", "inc");
        panic!();
    }

    // Get the most significant (len - s) bits
    let msb_bits = msb(bits, len - s);

    // Get the least significant s bits
    let lsb_bits = lsb(bits, s);

    // Convert the least significant s bits to an integer
    let mut lsb_value = 0;
    for bit in lsb_bits {
        lsb_value = (lsb_value << 1) | (bit as u64);
    }

    // Increment the integer modulo 2^s
    lsb_value = (lsb_value + 1) & ((1 << s) - 1);

    // Convert the incremented integer back to a bit string of length s
    let mut new_lsb_bits: BitVec = BitVec::with_capacity(s);
    for _ in 0..s {
        new_lsb_bits.push((lsb_value & 1) == 1);
        lsb_value >>= 1;
    }
    new_lsb_bits.reverse();

    // Concatenate the unchanged MSB with the incremented LSB
    let mut result = msb_bits;
    result.extend(new_lsb_bits);

    result
}


// This function adds two 128-bit blocks in place
fn block_add(block1: &mut BitVec, block2: &BitVec) {
    if block1.len() !=  block2.len() {
        println!("[{}] Error: Invalid block sizes: {}, {}", "block_add", block1.len(), block2.len());
        panic!();
    }

    block1.bitxor_assign(block2);
}

// This function computes the product of two 128-bit blocks
fn block_mult(x_block: &BitVec, y_block: &BitVec) -> BitVec {
    if x_block.len() != 128 || y_block.len() != 128 {
        panic!("[{}] Error: Invalid block sizes", "block_mult");
    }

    // This represents the irreducible polynomial modulus for GL(2^128)
    let mut r: BitVec = bitvec![1, 1, 1, 0, 0, 0, 0, 1];
    r.extend(bitvec![0; 120]);

    // Initialize Z_0 and V_0
    let mut z: BitVec = bitvec![0; 128];
    let mut v: BitVec = y_block.clone();

    for i in 0..128 {
        if x_block[i] {
            block_add(&mut z, &v);
        }

        if v[127] {
            v.shift_right(1);
            block_add(&mut v, &r);
        } else {
            v.shift_right(1);
        }
    }

    z
}

pub fn ghash(input: &BitVec, hash_subkey: &BitVec) -> BitVec {
    // Initialize the y block
    let mut y_block: BitVec = bitvec![0; 128];

    for chunk in input.chunks(128) {
        let chunk_bitvec: BitVec = chunk.to_bitvec();
        block_add(&mut y_block, &chunk_bitvec);
        y_block = block_mult(&mut y_block, hash_subkey);
    }

    y_block
}

// Galois/Counter Mode
pub fn gctr(icb: &BitVec, input: &BitVec, key: &[u8]) -> BitVec {
    if input.len() == 0 {
        return input.clone();
    }

    // Total number of blocks which can contain the input
    let num_blocks = (input.len() + 127) / 128;

    // Initialize the counter block
    let mut counter_block: BitVec = icb.to_bitvec();

    // Initialize y_blocks
    let mut y_blocks: BitVec = BitVec::with_capacity(input.len());

    for (i, chunk) in input.chunks(128).enumerate() {
        // Convert the counter block to bytes in order to send it to the block cipher
        let counter_block_bytes = bitslice_to_bytevec(&counter_block);

        // Encrypt the counter block and convert the result back to a BitVec
        let cipher_bits: BitVec = byteslice_to_bitvec(&aes_ecb_cipher(&counter_block_bytes, key));

        // Set x_block equal to the current 128 (or less) bit chunk in the input
        let mut x_block = chunk.to_bitvec();

        // XOR the encrypted counter block with the current x_block
        if i < num_blocks - 1 {
            block_add(&mut x_block, &cipher_bits);
        } else {
            // On the last iteration, in the case of a partial block, get the same number of significant bits 
            // as are in the number of bits in the last x_block and perform the XOR with those bits
            let cipher_msb = msb(&cipher_bits, x_block.len());
            block_add(&mut x_block, &cipher_msb);
        }
        
        // Append the XORed x_block to the y_blocks
        y_blocks.extend(x_block);

        // Increment the counter - happens here since first counter block was inititialized to ICB
        counter_block = inc(&counter_block, 32);
    }

    y_blocks
}

pub fn aes_ecb_cipher(block: &[u8], key: &[u8]) -> Vec<u8> {
    let key_schedule = key_expansion(key);

    // Convert the 16-byte block into the AES state matrix
    let mut state = [[0u8; 4]; 4];
    for i in 0..4 {
        for j in 0..4 {
            state[j][i] = block[i * 4 + j];
        }
    }

    // Perform the AES cipher operation
    cipher(&mut state, &key_schedule);

    // Convert the state matrix back into a 16-byte block
    let mut encrypted_block = [0u8; 16];
    for i in 0..4 {
        for j in 0..4 {
            encrypted_block[i * 4 + j] = state[j][i];
        }
    }

    encrypted_block.to_vec()
}

// NOTE: test_key_expansion() and test_ciphers() can only be tested if Nk == 8
//       These tests were run and passed at the time of this writing for 
//       Nk == 6 and Nk == 4, but due to Nk being global and several functions'
//       arguments being defined with Nk, it cannot be structured as conditional
//       on Nk.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_byte_product() {
        let b1: u8 = 0x57;
        let b2: u8 = 0x13;
        let p: u8 = prod(b1, b2);
        assert_eq!(0xfe, p);
    }

    #[test]
    fn test_key_expansion() {
        let key256: [u8; 32] = [0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,
                                0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
                                0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,
                                0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4];

        let exp_key: Vec<u32> = key_expansion(&key256);
        assert_eq!(0x706c631e, exp_key[exp_key.len()-1]);
    }

    #[test]
    fn test_ciphers() {        
        let key256: [u8; 32] = [0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,
                                0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
                                0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,
                                0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4];
    
        let mut post_state: [[u8; 4]; 4] = [[0x32, 0x88, 0x31, 0xe0],
                                       [0x43, 0x5a, 0x31, 0x37],
                                       [0xf6, 0x30, 0x98, 0x07],
                                       [0xa8, 0x8d, 0xa2, 0x34]];
        
        let pre_state: [[u8; 4]; 4] = post_state.clone();
        let exp_key: Vec<u32> = key_expansion(&key256);
        
        cipher(&mut post_state, &exp_key.clone());
        inv_cipher(&mut post_state, &exp_key.clone());
        assert_eq!(pre_state, post_state);
    }
}