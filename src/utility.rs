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