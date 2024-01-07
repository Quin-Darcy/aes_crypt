use crate::constants::BPB;
use crate::utility::least_multiple_greater_than;


#[derive(Debug)]
pub struct Data {
    pub bytes: Vec<u8>,
    pub states: Vec<[[u8; 4]; 4]>
}

impl Data {
    pub fn new() -> Self {
        Data {
            bytes: Vec::new(),
            states: Vec::new(),
        }
    }

    pub fn from_plaintext_bytes(raw_data: &[u8]) -> Self {
        // Compute the amount of padding needed. The total number of bytes 
        // needs to be a multiple of the block size, e.g., 16 bytes. We will always
        // add padding. This means if raw_data.len() % BPB == 0, we will add BPB 
        // bytes of padding. Thus, 1 <= padding_length <= BPB (bytes per block)
        let mut padding_len: usize = least_multiple_greater_than(BPB, raw_data.len()) - raw_data.len();

        if padding_len == 0 {
            padding_len = BPB;
        }

        let mut bytes: Vec<u8> = Vec::with_capacity(raw_data.len() + padding_len);

        // Extend the bytes vector with the raw data
        bytes.extend_from_slice(raw_data);

        // Implement the PKCS#7 Padding scheme
        assert!(padding_len <= u8::MAX as usize, "Padding Length out of range for u8");
        let padding_byte: u8 = padding_len as u8;
        let pad: Vec<u8> = vec![padding_byte; padding_len];
        bytes.extend(&pad);

        // Break the bytes vector into a vector of blocks
        let num_blocks: usize = bytes.len() / BPB;
        let mut blocks: Vec<[u8; BPB]> = Vec::with_capacity(num_blocks);
        let mut tmp_block = [0_u8; BPB];

        for i in 0..num_blocks {
            for j in 0..BPB { 
                tmp_block[j] = bytes[BPB*i+j]; 
            }
            blocks.push(tmp_block);
        }

        // Break the bytes vector into vector of 4x4 byte matrices (states)
        // Each successive group of 4 bytes forms a column in the matrix
        let mut states: Vec<[[u8; 4]; 4]> = Vec::with_capacity(num_blocks);
        let mut byte_matrix: [[u8; 4]; 4] = [[0_u8; 4]; 4];
        let mut tmp_column = [0_u8; 4];

        for i in 0..num_blocks {
            for j in 0..4 {
                for k in 0..4 {
                    tmp_column[k] = blocks[i][4*j+k];
                }
                byte_matrix[j] = tmp_column;
            }
            states.push(byte_matrix);
        }

        Data {
            bytes: bytes,
            states: states,
        }
    }

    pub fn from_cipher_text_bytes(raw_data: &[u8]) -> Self {
        // No padding is needed since the cipher text will have the same number of bytes
        // as the padded plain text which is already a multiple of block size
        let mut bytes: Vec<u8> = Vec::with_capacity(raw_data.len());

        // Extend the bytes vector with the raw data
        bytes.extend_from_slice(raw_data);

        // Break the bytes vector into a vector of blocks
        let num_blocks: usize = bytes.len() / BPB;
        let mut blocks: Vec<[u8; BPB]> = Vec::with_capacity(num_blocks);
        let mut tmp_block = [0_u8; BPB];

        for i in 0..num_blocks {
            for j in 0..BPB { 
                tmp_block[j] = bytes[BPB*i+j]; 
            }
            blocks.push(tmp_block);
        }

        // Break the bytes vector into vector of 4x4 byte matrices (states)
        // Each successive group of 4 bytes forms a column in the matrix
        let mut states: Vec<[[u8; 4]; 4]> = Vec::with_capacity(num_blocks);
        let mut byte_matrix: [[u8; 4]; 4] = [[0_u8; 4]; 4];
        let mut tmp_column = [0_u8; 4];

        for i in 0..num_blocks {
            for j in 0..4 {
                for k in 0..4 {
                    tmp_column[k] = blocks[i][4*j+k];
                }
                byte_matrix[j] = tmp_column;
            }
            states.push(byte_matrix);
        }

        Data {
            bytes: bytes,
            states: states,
        }
    }


    pub fn to_encrypted_bytes(&self) -> Vec<u8> {
        // Convert the states vector back into a flat vector of bytes
        let mut bytes: Vec<u8> = Vec::new();

        for byte_matrix in &self.states {
            for c in 0..4 {
                for r in 0..4 {
                    bytes.push(byte_matrix[c][r]);
                }
            }
        }

        if bytes.is_empty() {
            panic!("Encrypted data is empty");
        }

        bytes
    }

    pub fn to_decrypted_bytes(&self) -> Vec<u8> {
        // Convert the states vector back into a flat vector of bytes
        let mut bytes: Vec<u8> = Vec::new();

        for byte_matrix in &self.states {
            for c in 0..4 {
                for r in 0..4 {
                    bytes.push(byte_matrix[c][r]);
                }
            }
        }

        if bytes.is_empty() {
            panic!("Decrypted data is empty");
        }

        let num_bytes = bytes.len();

        // Since we are using the PKCS#7 padding scheme, the last byte
        // should represent the number of bytes added as padding
        let padding_len: usize = bytes[num_bytes - 1] as usize;

        // Verify this is a valid value, i.e., 1 <= padding_len <= BPB
        if padding_len == 0 || padding_len > BPB {
            println!("padding_len: {}", padding_len);
            panic!("Invalid padding length");
        }

        if padding_len > num_bytes {
            panic!("Padding length exceeds data length");
        }

        // Confirm that the last padding_len bytes of the bytes array are all
        // equal to padding_len as u8.
        let padding_byte: u8 = padding_len as u8;

        if !bytes.iter().skip(num_bytes - padding_len).all(|&b| b == padding_byte) {
            panic!("Invalid padding bytes");
        }

        // Remove the padding
        bytes.truncate(num_bytes - padding_len);

        bytes
    }
}