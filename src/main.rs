// Data input and output for the AES block ciphers are blocks
#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(non_upper_case_globals)]
#![allow(non_snake_case)]

const BINS: [[u8; 8]; 256] = [[0,0,0,0,0,0,0,0],[0,0,0,0,0,0,0,1],[0,0,0,0,0,0,1,0],[0,0,0,0,0,0,1,1],
                                [0,0,0,0,0,1,0,0],[0,0,0,0,0,1,0,1],[0,0,0,0,0,1,1,0],[0,0,0,0,0,1,1,1],
                                [0,0,0,0,1,0,0,0],[0,0,0,0,1,0,0,1],[0,0,0,0,1,0,1,0],[0,0,0,0,1,0,1,1],
                                [0,0,0,0,1,1,0,0],[0,0,0,0,1,1,0,1],[0,0,0,0,1,1,1,0],[0,0,0,0,1,1,1,1],
                                [0,0,0,1,0,0,0,0],[0,0,0,1,0,0,0,1],[0,0,0,1,0,0,1,0],[0,0,0,1,0,0,1,1],
                                [0,0,0,1,0,1,0,0],[0,0,0,1,0,1,0,1],[0,0,0,1,0,1,1,0],[0,0,0,1,0,1,1,1],
                                [0,0,0,1,1,0,0,0],[0,0,0,1,1,0,0,1],[0,0,0,1,1,0,1,0],[0,0,0,1,1,0,1,1],
                                [0,0,0,1,1,1,0,0],[0,0,0,1,1,1,0,1],[0,0,0,1,1,1,1,0],[0,0,0,1,1,1,1,1],
                                [0,0,1,0,0,0,0,0],[0,0,1,0,0,0,0,1],[0,0,1,0,0,0,1,0],[0,0,1,0,0,0,1,1],
                                [0,0,1,0,0,1,0,0],[0,0,1,0,0,1,0,1],[0,0,1,0,0,1,1,0],[0,0,1,0,0,1,1,1],
                                [0,0,1,0,1,0,0,0],[0,0,1,0,1,0,0,1],[0,0,1,0,1,0,1,0],[0,0,1,0,1,0,1,1],
                                [0,0,1,0,1,1,0,0],[0,0,1,0,1,1,0,1],[0,0,1,0,1,1,1,0],[0,0,1,0,1,1,1,1],
                                [0,0,1,1,0,0,0,0],[0,0,1,1,0,0,0,1],[0,0,1,1,0,0,1,0],[0,0,1,1,0,0,1,1],
                                [0,0,1,1,0,1,0,0],[0,0,1,1,0,1,0,1],[0,0,1,1,0,1,1,0],[0,0,1,1,0,1,1,1],
                                [0,0,1,1,1,0,0,0],[0,0,1,1,1,0,0,1],[0,0,1,1,1,0,1,0],[0,0,1,1,1,0,1,1],
                                [0,0,1,1,1,1,0,0],[0,0,1,1,1,1,0,1],[0,0,1,1,1,1,1,0],[0,0,1,1,1,1,1,1],
                                [0,1,0,0,0,0,0,0],[0,1,0,0,0,0,0,1],[0,1,0,0,0,0,1,0],[0,1,0,0,0,0,1,1],
                                [0,1,0,0,0,1,0,0],[0,1,0,0,0,1,0,1],[0,1,0,0,0,1,1,0],[0,1,0,0,0,1,1,1],
                                [0,1,0,0,1,0,0,0],[0,1,0,0,1,0,0,1],[0,1,0,0,1,0,1,0],[0,1,0,0,1,0,1,1],
                                [0,1,0,0,1,1,0,0],[0,1,0,0,1,1,0,1],[0,1,0,0,1,1,1,0],[0,1,0,0,1,1,1,1],
                                [0,1,0,1,0,0,0,0],[0,1,0,1,0,0,0,1],[0,1,0,1,0,0,1,0],[0,1,0,1,0,0,1,1],
                                [0,1,0,1,0,1,0,0],[0,1,0,1,0,1,0,1],[0,1,0,1,0,1,1,0],[0,1,0,1,0,1,1,1],
                                [0,1,0,1,1,0,0,0],[0,1,0,1,1,0,0,1],[0,1,0,1,1,0,1,0],[0,1,0,1,1,0,1,1],
                                [0,1,0,1,1,1,0,0],[0,1,0,1,1,1,0,1],[0,1,0,1,1,1,1,0],[0,1,0,1,1,1,1,1],
                                [0,1,1,0,0,0,0,0],[0,1,1,0,0,0,0,1],[0,1,1,0,0,0,1,0],[0,1,1,0,0,0,1,1],
                                [0,1,1,0,0,1,0,0],[0,1,1,0,0,1,0,1],[0,1,1,0,0,1,1,0],[0,1,1,0,0,1,1,1],
                                [0,1,1,0,1,0,0,0],[0,1,1,0,1,0,0,1],[0,1,1,0,1,0,1,0],[0,1,1,0,1,0,1,1],
                                [0,1,1,0,1,1,0,0],[0,1,1,0,1,1,0,1],[0,1,1,0,1,1,1,0],[0,1,1,0,1,1,1,1],
                                [0,1,1,1,0,0,0,0],[0,1,1,1,0,0,0,1],[0,1,1,1,0,0,1,0],[0,1,1,1,0,0,1,1],
                                [0,1,1,1,0,1,0,0],[0,1,1,1,0,1,0,1],[0,1,1,1,0,1,1,0],[0,1,1,1,0,1,1,1],
                                [0,1,1,1,1,0,0,0],[0,1,1,1,1,0,0,1],[0,1,1,1,1,0,1,0],[0,1,1,1,1,0,1,1],
                                [0,1,1,1,1,1,0,0],[0,1,1,1,1,1,0,1],[0,1,1,1,1,1,1,0],[0,1,1,1,1,1,1,1],
                                [1,0,0,0,0,0,0,0],[1,0,0,0,0,0,0,1],[1,0,0,0,0,0,1,0],[1,0,0,0,0,0,1,1],
                                [1,0,0,0,0,1,0,0],[1,0,0,0,0,1,0,1],[1,0,0,0,0,1,1,0],[1,0,0,0,0,1,1,1],
                                [1,0,0,0,1,0,0,0],[1,0,0,0,1,0,0,1],[1,0,0,0,1,0,1,0],[1,0,0,0,1,0,1,1],
                                [1,0,0,0,1,1,0,0],[1,0,0,0,1,1,0,1],[1,0,0,0,1,1,1,0],[1,0,0,0,1,1,1,1],
                                [1,0,0,1,0,0,0,0],[1,0,0,1,0,0,0,1],[1,0,0,1,0,0,1,0],[1,0,0,1,0,0,1,1],
                                [1,0,0,1,0,1,0,0],[1,0,0,1,0,1,0,1],[1,0,0,1,0,1,1,0],[1,0,0,1,0,1,1,1],
                                [1,0,0,1,1,0,0,0],[1,0,0,1,1,0,0,1],[1,0,0,1,1,0,1,0],[1,0,0,1,1,0,1,1],
                                [1,0,0,1,1,1,0,0],[1,0,0,1,1,1,0,1],[1,0,0,1,1,1,1,0],[1,0,0,1,1,1,1,1],
                                [1,0,1,0,0,0,0,0],[1,0,1,0,0,0,0,1],[1,0,1,0,0,0,1,0],[1,0,1,0,0,0,1,1],
                                [1,0,1,0,0,1,0,0],[1,0,1,0,0,1,0,1],[1,0,1,0,0,1,1,0],[1,0,1,0,0,1,1,1],
                                [1,0,1,0,1,0,0,0],[1,0,1,0,1,0,0,1],[1,0,1,0,1,0,1,0],[1,0,1,0,1,0,1,1],
                                [1,0,1,0,1,1,0,0],[1,0,1,0,1,1,0,1],[1,0,1,0,1,1,1,0],[1,0,1,0,1,1,1,1],
                                [1,0,1,1,0,0,0,0],[1,0,1,1,0,0,0,1],[1,0,1,1,0,0,1,0],[1,0,1,1,0,0,1,1],
                                [1,0,1,1,0,1,0,0],[1,0,1,1,0,1,0,1],[1,0,1,1,0,1,1,0],[1,0,1,1,0,1,1,1],
                                [1,0,1,1,1,0,0,0],[1,0,1,1,1,0,0,1],[1,0,1,1,1,0,1,0],[1,0,1,1,1,0,1,1],
                                [1,0,1,1,1,1,0,0],[1,0,1,1,1,1,0,1],[1,0,1,1,1,1,1,0],[1,0,1,1,1,1,1,1],
                                [1,1,0,0,0,0,0,0],[1,1,0,0,0,0,0,1],[1,1,0,0,0,0,1,0],[1,1,0,0,0,0,1,1],
                                [1,1,0,0,0,1,0,0],[1,1,0,0,0,1,0,1],[1,1,0,0,0,1,1,0],[1,1,0,0,0,1,1,1],
                                [1,1,0,0,1,0,0,0],[1,1,0,0,1,0,0,1],[1,1,0,0,1,0,1,0],[1,1,0,0,1,0,1,1],
                                [1,1,0,0,1,1,0,0],[1,1,0,0,1,1,0,1],[1,1,0,0,1,1,1,0],[1,1,0,0,1,1,1,1],
                                [1,1,0,1,0,0,0,0],[1,1,0,1,0,0,0,1],[1,1,0,1,0,0,1,0],[1,1,0,1,0,0,1,1],
                                [1,1,0,1,0,1,0,0],[1,1,0,1,0,1,0,1],[1,1,0,1,0,1,1,0],[1,1,0,1,0,1,1,1],
                                [1,1,0,1,1,0,0,0],[1,1,0,1,1,0,0,1],[1,1,0,1,1,0,1,0],[1,1,0,1,1,0,1,1],
                                [1,1,0,1,1,1,0,0],[1,1,0,1,1,1,0,1],[1,1,0,1,1,1,1,0],[1,1,0,1,1,1,1,1],
                                [1,1,1,0,0,0,0,0],[1,1,1,0,0,0,0,1],[1,1,1,0,0,0,1,0],[1,1,1,0,0,0,1,1],
                                [1,1,1,0,0,1,0,0],[1,1,1,0,0,1,0,1],[1,1,1,0,0,1,1,0],[1,1,1,0,0,1,1,1],
                                [1,1,1,0,1,0,0,0],[1,1,1,0,1,0,0,1],[1,1,1,0,1,0,1,0],[1,1,1,0,1,0,1,1],
                                [1,1,1,0,1,1,0,0],[1,1,1,0,1,1,0,1],[1,1,1,0,1,1,1,0],[1,1,1,0,1,1,1,1],
                                [1,1,1,1,0,0,0,0],[1,1,1,1,0,0,0,1],[1,1,1,1,0,0,1,0],[1,1,1,1,0,0,1,1],
                                [1,1,1,1,0,1,0,0],[1,1,1,1,0,1,0,1],[1,1,1,1,0,1,1,0],[1,1,1,1,0,1,1,1],
                                [1,1,1,1,1,0,0,0],[1,1,1,1,1,0,0,1],[1,1,1,1,1,0,1,0],[1,1,1,1,1,0,1,1],
                                [1,1,1,1,1,1,0,0],[1,1,1,1,1,1,0,1],[1,1,1,1,1,1,1,0],[1,1,1,1,1,1,1,1]];


// XPOW_PRODS[i][j] = (x^i)*j (as polynomials)
const XPOW_PRODS: [[u8; 256]; 8] = [[0x0,0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,0x9,0xa,0xb,0xc,0xd,0xe,0xf,
                                0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,
                                0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f,
                                0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x3a,0x3b,0x3c,0x3d,0x3e,0x3f,
                                0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x49,0x4a,0x4b,0x4c,0x4d,0x4e,0x4f,
                                0x50,0x51,0x52,0x53,0x54,0x55,0x56,0x57,0x58,0x59,0x5a,0x5b,0x5c,0x5d,0x5e,0x5f,
                                0x60,0x61,0x62,0x63,0x64,0x65,0x66,0x67,0x68,0x69,0x6a,0x6b,0x6c,0x6d,0x6e,0x6f,
                                0x70,0x71,0x72,0x73,0x74,0x75,0x76,0x77,0x78,0x79,0x7a,0x7b,0x7c,0x7d,0x7e,0x7f,
                                0x80,0x81,0x82,0x83,0x84,0x85,0x86,0x87,0x88,0x89,0x8a,0x8b,0x8c,0x8d,0x8e,0x8f,
                                0x90,0x91,0x92,0x93,0x94,0x95,0x96,0x97,0x98,0x99,0x9a,0x9b,0x9c,0x9d,0x9e,0x9f,
                                0xa0,0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7,0xa8,0xa9,0xaa,0xab,0xac,0xad,0xae,0xaf,
                                0xb0,0xb1,0xb2,0xb3,0xb4,0xb5,0xb6,0xb7,0xb8,0xb9,0xba,0xbb,0xbc,0xbd,0xbe,0xbf,
                                0xc0,0xc1,0xc2,0xc3,0xc4,0xc5,0xc6,0xc7,0xc8,0xc9,0xca,0xcb,0xcc,0xcd,0xce,0xcf,
                                0xd0,0xd1,0xd2,0xd3,0xd4,0xd5,0xd6,0xd7,0xd8,0xd9,0xda,0xdb,0xdc,0xdd,0xde,0xdf,
                                0xe0,0xe1,0xe2,0xe3,0xe4,0xe5,0xe6,0xe7,0xe8,0xe9,0xea,0xeb,0xec,0xed,0xee,0xef,
                                0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,0xf9,0xfa,0xfb,0xfc,0xfd,0xfe,0xff],

                                [0x0,0x2,0x4,0x6,0x8,0xa,0xc,0xe,0x10,0x12,0x14,0x16,0x18,0x1a,0x1c,0x1e,
                                0x20,0x22,0x24,0x26,0x28,0x2a,0x2c,0x2e,0x30,0x32,0x34,0x36,0x38,0x3a,0x3c,0x3e,
                                0x40,0x42,0x44,0x46,0x48,0x4a,0x4c,0x4e,0x50,0x52,0x54,0x56,0x58,0x5a,0x5c,0x5e,
                                0x60,0x62,0x64,0x66,0x68,0x6a,0x6c,0x6e,0x70,0x72,0x74,0x76,0x78,0x7a,0x7c,0x7e,
                                0x80,0x82,0x84,0x86,0x88,0x8a,0x8c,0x8e,0x90,0x92,0x94,0x96,0x98,0x9a,0x9c,0x9e,
                                0xa0,0xa2,0xa4,0xa6,0xa8,0xaa,0xac,0xae,0xb0,0xb2,0xb4,0xb6,0xb8,0xba,0xbc,0xbe,
                                0xc0,0xc2,0xc4,0xc6,0xc8,0xca,0xcc,0xce,0xd0,0xd2,0xd4,0xd6,0xd8,0xda,0xdc,0xde,
                                0xe0,0xe2,0xe4,0xe6,0xe8,0xea,0xec,0xee,0xf0,0xf2,0xf4,0xf6,0xf8,0xfa,0xfc,0xfe,
                                0x1b,0x19,0x1f,0x1d,0x13,0x11,0x17,0x15,0xb,0x9,0xf,0xd,0x3,0x1,0x7,0x5,
                                0x3b,0x39,0x3f,0x3d,0x33,0x31,0x37,0x35,0x2b,0x29,0x2f,0x2d,0x23,0x21,0x27,0x25,
                                0x5b,0x59,0x5f,0x5d,0x53,0x51,0x57,0x55,0x4b,0x49,0x4f,0x4d,0x43,0x41,0x47,0x45,
                                0x7b,0x79,0x7f,0x7d,0x73,0x71,0x77,0x75,0x6b,0x69,0x6f,0x6d,0x63,0x61,0x67,0x65,
                                0x9b,0x99,0x9f,0x9d,0x93,0x91,0x97,0x95,0x8b,0x89,0x8f,0x8d,0x83,0x81,0x87,0x85,
                                0xbb,0xb9,0xbf,0xbd,0xb3,0xb1,0xb7,0xb5,0xab,0xa9,0xaf,0xad,0xa3,0xa1,0xa7,0xa5,
                                0xdb,0xd9,0xdf,0xdd,0xd3,0xd1,0xd7,0xd5,0xcb,0xc9,0xcf,0xcd,0xc3,0xc1,0xc7,0xc5,
                                0xfb,0xf9,0xff,0xfd,0xf3,0xf1,0xf7,0xf5,0xeb,0xe9,0xef,0xed,0xe3,0xe1,0xe7,0xe5],

                                [0x0,0x4,0x8,0xc,0x10,0x14,0x18,0x1c,0x20,0x24,0x28,0x2c,0x30,0x34,0x38,0x3c,
                                0x40,0x44,0x48,0x4c,0x50,0x54,0x58,0x5c,0x60,0x64,0x68,0x6c,0x70,0x74,0x78,0x7c,
                                0x80,0x84,0x88,0x8c,0x90,0x94,0x98,0x9c,0xa0,0xa4,0xa8,0xac,0xb0,0xb4,0xb8,0xbc,
                                0xc0,0xc4,0xc8,0xcc,0xd0,0xd4,0xd8,0xdc,0xe0,0xe4,0xe8,0xec,0xf0,0xf4,0xf8,0xfc,
                                0x1b,0x1f,0x13,0x17,0xb,0xf,0x3,0x7,0x3b,0x3f,0x33,0x37,0x2b,0x2f,0x23,0x27,
                                0x5b,0x5f,0x53,0x57,0x4b,0x4f,0x43,0x47,0x7b,0x7f,0x73,0x77,0x6b,0x6f,0x63,0x67,
                                0x9b,0x9f,0x93,0x97,0x8b,0x8f,0x83,0x87,0xbb,0xbf,0xb3,0xb7,0xab,0xaf,0xa3,0xa7,
                                0xdb,0xdf,0xd3,0xd7,0xcb,0xcf,0xc3,0xc7,0xfb,0xff,0xf3,0xf7,0xeb,0xef,0xe3,0xe7,
                                0x36,0x32,0x3e,0x3a,0x26,0x22,0x2e,0x2a,0x16,0x12,0x1e,0x1a,0x6,0x2,0xe,0xa,
                                0x76,0x72,0x7e,0x7a,0x66,0x62,0x6e,0x6a,0x56,0x52,0x5e,0x5a,0x46,0x42,0x4e,0x4a,
                                0xb6,0xb2,0xbe,0xba,0xa6,0xa2,0xae,0xaa,0x96,0x92,0x9e,0x9a,0x86,0x82,0x8e,0x8a,
                                0xf6,0xf2,0xfe,0xfa,0xe6,0xe2,0xee,0xea,0xd6,0xd2,0xde,0xda,0xc6,0xc2,0xce,0xca,
                                0x2d,0x29,0x25,0x21,0x3d,0x39,0x35,0x31,0xd,0x9,0x5,0x1,0x1d,0x19,0x15,0x11,
                                0x6d,0x69,0x65,0x61,0x7d,0x79,0x75,0x71,0x4d,0x49,0x45,0x41,0x5d,0x59,0x55,0x51,
                                0xad,0xa9,0xa5,0xa1,0xbd,0xb9,0xb5,0xb1,0x8d,0x89,0x85,0x81,0x9d,0x99,0x95,0x91,
                                0xed,0xe9,0xe5,0xe1,0xfd,0xf9,0xf5,0xf1,0xcd,0xc9,0xc5,0xc1,0xdd,0xd9,0xd5,0xd1],

                                [0x0,0x8,0x10,0x18,0x20,0x28,0x30,0x38,0x40,0x48,0x50,0x58,0x60,0x68,0x70,0x78,
                                0x80,0x88,0x90,0x98,0xa0,0xa8,0xb0,0xb8,0xc0,0xc8,0xd0,0xd8,0xe0,0xe8,0xf0,0xf8,
                                0x1b,0x13,0xb,0x3,0x3b,0x33,0x2b,0x23,0x5b,0x53,0x4b,0x43,0x7b,0x73,0x6b,0x63,
                                0x9b,0x93,0x8b,0x83,0xbb,0xb3,0xab,0xa3,0xdb,0xd3,0xcb,0xc3,0xfb,0xf3,0xeb,0xe3,
                                0x36,0x3e,0x26,0x2e,0x16,0x1e,0x6,0xe,0x76,0x7e,0x66,0x6e,0x56,0x5e,0x46,0x4e,
                                0xb6,0xbe,0xa6,0xae,0x96,0x9e,0x86,0x8e,0xf6,0xfe,0xe6,0xee,0xd6,0xde,0xc6,0xce,
                                0x2d,0x25,0x3d,0x35,0xd,0x5,0x1d,0x15,0x6d,0x65,0x7d,0x75,0x4d,0x45,0x5d,0x55,
                                0xad,0xa5,0xbd,0xb5,0x8d,0x85,0x9d,0x95,0xed,0xe5,0xfd,0xf5,0xcd,0xc5,0xdd,0xd5,
                                0x6c,0x64,0x7c,0x74,0x4c,0x44,0x5c,0x54,0x2c,0x24,0x3c,0x34,0xc,0x4,0x1c,0x14,
                                0xec,0xe4,0xfc,0xf4,0xcc,0xc4,0xdc,0xd4,0xac,0xa4,0xbc,0xb4,0x8c,0x84,0x9c,0x94,
                                0x77,0x7f,0x67,0x6f,0x57,0x5f,0x47,0x4f,0x37,0x3f,0x27,0x2f,0x17,0x1f,0x7,0xf,
                                0xf7,0xff,0xe7,0xef,0xd7,0xdf,0xc7,0xcf,0xb7,0xbf,0xa7,0xaf,0x97,0x9f,0x87,0x8f,
                                0x5a,0x52,0x4a,0x42,0x7a,0x72,0x6a,0x62,0x1a,0x12,0xa,0x2,0x3a,0x32,0x2a,0x22,
                                0xda,0xd2,0xca,0xc2,0xfa,0xf2,0xea,0xe2,0x9a,0x92,0x8a,0x82,0xba,0xb2,0xaa,0xa2,
                                0x41,0x49,0x51,0x59,0x61,0x69,0x71,0x79,0x1,0x9,0x11,0x19,0x21,0x29,0x31,0x39,
                                0xc1,0xc9,0xd1,0xd9,0xe1,0xe9,0xf1,0xf9,0x81,0x89,0x91,0x99,0xa1,0xa9,0xb1,0xb9],

                                [0x0,0x10,0x20,0x30,0x40,0x50,0x60,0x70,0x80,0x90,0xa0,0xb0,0xc0,0xd0,0xe0,0xf0,
                                0x1b,0xb,0x3b,0x2b,0x5b,0x4b,0x7b,0x6b,0x9b,0x8b,0xbb,0xab,0xdb,0xcb,0xfb,0xeb,
                                0x36,0x26,0x16,0x6,0x76,0x66,0x56,0x46,0xb6,0xa6,0x96,0x86,0xf6,0xe6,0xd6,0xc6,
                                0x2d,0x3d,0xd,0x1d,0x6d,0x7d,0x4d,0x5d,0xad,0xbd,0x8d,0x9d,0xed,0xfd,0xcd,0xdd,
                                0x6c,0x7c,0x4c,0x5c,0x2c,0x3c,0xc,0x1c,0xec,0xfc,0xcc,0xdc,0xac,0xbc,0x8c,0x9c,
                                0x77,0x67,0x57,0x47,0x37,0x27,0x17,0x7,0xf7,0xe7,0xd7,0xc7,0xb7,0xa7,0x97,0x87,
                                0x5a,0x4a,0x7a,0x6a,0x1a,0xa,0x3a,0x2a,0xda,0xca,0xfa,0xea,0x9a,0x8a,0xba,0xaa,
                                0x41,0x51,0x61,0x71,0x1,0x11,0x21,0x31,0xc1,0xd1,0xe1,0xf1,0x81,0x91,0xa1,0xb1,
                                0xd8,0xc8,0xf8,0xe8,0x98,0x88,0xb8,0xa8,0x58,0x48,0x78,0x68,0x18,0x8,0x38,0x28,
                                0xc3,0xd3,0xe3,0xf3,0x83,0x93,0xa3,0xb3,0x43,0x53,0x63,0x73,0x3,0x13,0x23,0x33,
                                0xee,0xfe,0xce,0xde,0xae,0xbe,0x8e,0x9e,0x6e,0x7e,0x4e,0x5e,0x2e,0x3e,0xe,0x1e,
                                0xf5,0xe5,0xd5,0xc5,0xb5,0xa5,0x95,0x85,0x75,0x65,0x55,0x45,0x35,0x25,0x15,0x5,
                                0xb4,0xa4,0x94,0x84,0xf4,0xe4,0xd4,0xc4,0x34,0x24,0x14,0x4,0x74,0x64,0x54,0x44,
                                0xaf,0xbf,0x8f,0x9f,0xef,0xff,0xcf,0xdf,0x2f,0x3f,0xf,0x1f,0x6f,0x7f,0x4f,0x5f,
                                0x82,0x92,0xa2,0xb2,0xc2,0xd2,0xe2,0xf2,0x2,0x12,0x22,0x32,0x42,0x52,0x62,0x72,
                                0x99,0x89,0xb9,0xa9,0xd9,0xc9,0xf9,0xe9,0x19,0x9,0x39,0x29,0x59,0x49,0x79,0x69],

                                [0x0,0x20,0x40,0x60,0x80,0xa0,0xc0,0xe0,0x1b,0x3b,0x5b,0x7b,0x9b,0xbb,0xdb,0xfb,
                                0x36,0x16,0x76,0x56,0xb6,0x96,0xf6,0xd6,0x2d,0xd,0x6d,0x4d,0xad,0x8d,0xed,0xcd,
                                0x6c,0x4c,0x2c,0xc,0xec,0xcc,0xac,0x8c,0x77,0x57,0x37,0x17,0xf7,0xd7,0xb7,0x97,
                                0x5a,0x7a,0x1a,0x3a,0xda,0xfa,0x9a,0xba,0x41,0x61,0x1,0x21,0xc1,0xe1,0x81,0xa1,
                                0xd8,0xf8,0x98,0xb8,0x58,0x78,0x18,0x38,0xc3,0xe3,0x83,0xa3,0x43,0x63,0x3,0x23,
                                0xee,0xce,0xae,0x8e,0x6e,0x4e,0x2e,0xe,0xf5,0xd5,0xb5,0x95,0x75,0x55,0x35,0x15,
                                0xb4,0x94,0xf4,0xd4,0x34,0x14,0x74,0x54,0xaf,0x8f,0xef,0xcf,0x2f,0xf,0x6f,0x4f,
                                0x82,0xa2,0xc2,0xe2,0x2,0x22,0x42,0x62,0x99,0xb9,0xd9,0xf9,0x19,0x39,0x59,0x79,
                                0xab,0x8b,0xeb,0xcb,0x2b,0xb,0x6b,0x4b,0xb0,0x90,0xf0,0xd0,0x30,0x10,0x70,0x50,
                                0x9d,0xbd,0xdd,0xfd,0x1d,0x3d,0x5d,0x7d,0x86,0xa6,0xc6,0xe6,0x6,0x26,0x46,0x66,
                                0xc7,0xe7,0x87,0xa7,0x47,0x67,0x7,0x27,0xdc,0xfc,0x9c,0xbc,0x5c,0x7c,0x1c,0x3c,
                                0xf1,0xd1,0xb1,0x91,0x71,0x51,0x31,0x11,0xea,0xca,0xaa,0x8a,0x6a,0x4a,0x2a,0xa,
                                0x73,0x53,0x33,0x13,0xf3,0xd3,0xb3,0x93,0x68,0x48,0x28,0x8,0xe8,0xc8,0xa8,0x88,
                                0x45,0x65,0x5,0x25,0xc5,0xe5,0x85,0xa5,0x5e,0x7e,0x1e,0x3e,0xde,0xfe,0x9e,0xbe,
                                0x1f,0x3f,0x5f,0x7f,0x9f,0xbf,0xdf,0xff,0x4,0x24,0x44,0x64,0x84,0xa4,0xc4,0xe4,
                                0x29,0x9,0x69,0x49,0xa9,0x89,0xe9,0xc9,0x32,0x12,0x72,0x52,0xb2,0x92,0xf2,0xd2],

                                [0x0,0x40,0x80,0xc0,0x1b,0x5b,0x9b,0xdb,0x36,0x76,0xb6,0xf6,0x2d,0x6d,0xad,0xed,
                                0x6c,0x2c,0xec,0xac,0x77,0x37,0xf7,0xb7,0x5a,0x1a,0xda,0x9a,0x41,0x1,0xc1,0x81,
                                0xd8,0x98,0x58,0x18,0xc3,0x83,0x43,0x3,0xee,0xae,0x6e,0x2e,0xf5,0xb5,0x75,0x35,
                                0xb4,0xf4,0x34,0x74,0xaf,0xef,0x2f,0x6f,0x82,0xc2,0x2,0x42,0x99,0xd9,0x19,0x59,
                                0xab,0xeb,0x2b,0x6b,0xb0,0xf0,0x30,0x70,0x9d,0xdd,0x1d,0x5d,0x86,0xc6,0x6,0x46,
                                0xc7,0x87,0x47,0x7,0xdc,0x9c,0x5c,0x1c,0xf1,0xb1,0x71,0x31,0xea,0xaa,0x6a,0x2a,
                                0x73,0x33,0xf3,0xb3,0x68,0x28,0xe8,0xa8,0x45,0x5,0xc5,0x85,0x5e,0x1e,0xde,0x9e,
                                0x1f,0x5f,0x9f,0xdf,0x4,0x44,0x84,0xc4,0x29,0x69,0xa9,0xe9,0x32,0x72,0xb2,0xf2,
                                0x4d,0xd,0xcd,0x8d,0x56,0x16,0xd6,0x96,0x7b,0x3b,0xfb,0xbb,0x60,0x20,0xe0,0xa0,
                                0x21,0x61,0xa1,0xe1,0x3a,0x7a,0xba,0xfa,0x17,0x57,0x97,0xd7,0xc,0x4c,0x8c,0xcc,
                                0x95,0xd5,0x15,0x55,0x8e,0xce,0xe,0x4e,0xa3,0xe3,0x23,0x63,0xb8,0xf8,0x38,0x78,
                                0xf9,0xb9,0x79,0x39,0xe2,0xa2,0x62,0x22,0xcf,0x8f,0x4f,0xf,0xd4,0x94,0x54,0x14,
                                0xe6,0xa6,0x66,0x26,0xfd,0xbd,0x7d,0x3d,0xd0,0x90,0x50,0x10,0xcb,0x8b,0x4b,0xb,
                                0x8a,0xca,0xa,0x4a,0x91,0xd1,0x11,0x51,0xbc,0xfc,0x3c,0x7c,0xa7,0xe7,0x27,0x67,
                                0x3e,0x7e,0xbe,0xfe,0x25,0x65,0xa5,0xe5,0x8,0x48,0x88,0xc8,0x13,0x53,0x93,0xd3,
                                0x52,0x12,0xd2,0x92,0x49,0x9,0xc9,0x89,0x64,0x24,0xe4,0xa4,0x7f,0x3f,0xff,0xbf],

                                [0x0,0x80,0x1b,0x9b,0x36,0xb6,0x2d,0xad,0x6c,0xec,0x77,0xf7,0x5a,0xda,0x41,0xc1,
                                0xd8,0x58,0xc3,0x43,0xee,0x6e,0xf5,0x75,0xb4,0x34,0xaf,0x2f,0x82,0x2,0x99,0x19,
                                0xab,0x2b,0xb0,0x30,0x9d,0x1d,0x86,0x6,0xc7,0x47,0xdc,0x5c,0xf1,0x71,0xea,0x6a,
                                0x73,0xf3,0x68,0xe8,0x45,0xc5,0x5e,0xde,0x1f,0x9f,0x4,0x84,0x29,0xa9,0x32,0xb2,
                                0x4d,0xcd,0x56,0xd6,0x7b,0xfb,0x60,0xe0,0x21,0xa1,0x3a,0xba,0x17,0x97,0xc,0x8c,
                                0x95,0x15,0x8e,0xe,0xa3,0x23,0xb8,0x38,0xf9,0x79,0xe2,0x62,0xcf,0x4f,0xd4,0x54,
                                0xe6,0x66,0xfd,0x7d,0xd0,0x50,0xcb,0x4b,0x8a,0xa,0x91,0x11,0xbc,0x3c,0xa7,0x27,
                                0x3e,0xbe,0x25,0xa5,0x8,0x88,0x13,0x93,0x52,0xd2,0x49,0xc9,0x64,0xe4,0x7f,0xff,
                                0x9a,0x1a,0x81,0x1,0xac,0x2c,0xb7,0x37,0xf6,0x76,0xed,0x6d,0xc0,0x40,0xdb,0x5b,
                                0x42,0xc2,0x59,0xd9,0x74,0xf4,0x6f,0xef,0x2e,0xae,0x35,0xb5,0x18,0x98,0x3,0x83,
                                0x31,0xb1,0x2a,0xaa,0x7,0x87,0x1c,0x9c,0x5d,0xdd,0x46,0xc6,0x6b,0xeb,0x70,0xf0,
                                0xe9,0x69,0xf2,0x72,0xdf,0x5f,0xc4,0x44,0x85,0x5,0x9e,0x1e,0xb3,0x33,0xa8,0x28,
                                0xd7,0x57,0xcc,0x4c,0xe1,0x61,0xfa,0x7a,0xbb,0x3b,0xa0,0x20,0x8d,0xd,0x96,0x16,
                                0xf,0x8f,0x14,0x94,0x39,0xb9,0x22,0xa2,0x63,0xe3,0x78,0xf8,0x55,0xd5,0x4e,0xce,
                                0x7c,0xfc,0x67,0xe7,0x4a,0xca,0x51,0xd1,0x10,0x90,0xb,0x8b,0x26,0xa6,0x3d,0xbd,
                                0xa4,0x24,0xbf,0x3f,0x92,0x12,0x89,0x9,0xc8,0x48,0xd3,0x53,0xfe,0x7e,0xe5,0x65]];

// Look up table for all multiplicative inverses in Z_2[X] / (P)_i
const INVERSES: [u8; 255] = [1,141,246,203,82,123,209,232,79,41,192,176,225,229,199,116,
                             180,170,75,153,43,96,95,88,63,253,204,255,64,238,178,58,
                             110,90,241,85,77,168,201,193,10,152,21,48,68,162,194,44,
                             69,146,108,243,57,102,66,242,53,32,111,119,187,89,25,29,
                             254,55,103,45,49,245,105,167,100,171,19,84,37,233,9,237,
                             92,5,202,76,36,135,191,24,62,34,240,81,236,97,23,22,
                             94,175,211,73,166,54,67,244,71,145,223,51,147,33,59,121,
                             183,151,133,16,181,186,60,182,112,208,6,161,250,129,130,131,
                             126,127,128,150,115,190,86,155,158,149,217,247,2,185,164,222,
                             106,50,109,216,138,132,114,42,20,159,136,249,220,137,154,251,
                             124,46,195,143,184,101,72,38,200,18,74,206,231,210,98,12,
                             224,31,239,17,117,120,113,165,142,118,61,189,188,134,87,11,
                             40,47,163,218,212,228,15,169,39,83,4,27,252,172,230,122,
                             7,174,99,197,219,226,234,148,139,196,213,157,248,144,107,177,
                             13,214,235,198,14,207,173,8,78,215,227,93,80,30,179,91,
                             35,56,52,104,70,3,140,221,156,125,160,205,26,65,28];


const SBOX: [u8; 256] = [0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
                         0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
                         0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
                         0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
                         0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
                         0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
                         0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
                         0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
                         0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
                         0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
                         0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
                         0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
                         0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
                         0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
                         0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
                         0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16];

const RCON: [[u8; 4]; 10] = [[0x01,0x00,0x00,0x00],[0x02,0x00,0x00,0x00],[0x04,0x00,0x00,0x00],[0x08,0x00,0x00,0x00],[0x10,0x00,0x00,0x00],
                             [0x20,0x00,0x00,0x00],[0x40,0x00,0x00,0x00],[0x80,0x00,0x00,0x00],[0x1b,0x00,0x00,0x00],[0x36,0x00,0x00,0x00]];

// Cache which fills during runtime containing all products taken throughout runtime
static mut GLOBAL_PRODUCT_CACHE: [[u8; 256]; 256] = [[0_u8; 256]; 256];

// Key length = 32 * Nk
const Nk: u32 = 8;

// Blocksize -- always 128
const Nb: u32 = 128;

fn bin_to_byte(bin:  [u8; 8]) -> u8 {
    let mut dec: u8 = 0;

    for i in 0..8 {
        dec += bin[8-1-i] * 2_u8.pow(i as u32);
    }
    dec
}

// Tested and optimized with GPT
fn dot(w1: [u8; 4], w2: [u8; 4]) -> u8 {
    /*
    let mut dp: u8 = 0;
    for i in 0..4 {
        dp = dp ^ prod(w1[i], w2[i]);
    }
    return dp;
    */
    w1.iter().zip(w2.iter()).fold(0, |acc, (&a, &b)| acc ^ prod(a, b))
}

// Tested
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

// Tested
fn sub_bytes(state: &mut [[u8; 4]; 4]) {
    for i in 0..4 {
        for j in 0..4 {
            state[i][j] = SBOX[state[i][j] as usize];
        }
    } 
}

// Tested
fn shift_rows(state: &mut [[u8; 4]; 4]) {
    let mut new_state: [[u8; 4]; 4] = [[0_u8; 4]; 4];

    for i in 0..4 {
        for j in 0..4 {
            new_state[i][j] = state[i][(i+j)%4];
        }
    }
    *state = new_state;
}

// Tested
fn mix_columns(state: &mut [[u8; 4]; 4]) {
    let state_copy: [[u8; 4]; 4] = (*state).clone();
    let mat: [[u8; 4]; 4] = [[0x02, 0x03, 0x01, 0x01],
                             [0x01, 0x02, 0x03, 0x01],
                             [0x01, 0x01, 0x02, 0x03],
                             [0x03, 0x01, 0x01, 0x02]];
    
    for i in 0..4 {
        let c: [u8; 4] = [state_copy[0][i], state_copy[1][i], state_copy[2][i], state_copy[3][i]];
        for j in 0..4 {
            state[j][i] = dot(mat[j], c); 
        }
    }
}

// Tested (128, 192, 256)
fn key_expansion(key: [u8; 4*Nk as usize]) -> Vec<u32> {
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

    let mut temp: u32 = 0;
    let Rcon: [u32; 10] = [0x01000000,0x02000000,0x04000000,0x08000000,0x10000000,
                           0x20000000,0x40000000,0x80000000,0x1b000000,0x36000000];
    while i <= 4*Nr+3 {
        temp = w[(i-1) as usize];
        if i % Nk == 0 {
            temp = sub_word(rot_word(temp)) ^ Rcon[(i/Nk-1) as usize];
        } else if Nk > 6 && i % Nk == 4 {
            temp = sub_word(temp);
        }
        w.push(w[(i-Nk) as usize]^temp);
        i += 1;
    }
    return w;
} 

fn main() {
    let key128: [u8; 16] = [0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c];
    
    let key192: [u8; 24] = [0x8e,0x73,0xb0,0xf7,0xda,0x0e,0x64,0x52,0xc8,0x10,0xf3,0x2b,
                            0x80,0x90,0x79,0xe5,0x62,0xf8,0xea,0xd2,0x52,0x2c,0x6b,0x7b];

    let key256: [u8; 32] = [0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
                            0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4];
    
    let mut state: [[u8; 4]; 4] = [[0x32, 0x88, 0x31, 0xe0],
                                   [0x43, 0x5a, 0x31, 0x37],
                                   [0xf6, 0x30, 0x98, 0x07],
                                   [0xa8, 0x8d, 0xa2, 0x34]];
    
    
    key_expansion(key256);
}
