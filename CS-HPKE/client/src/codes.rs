pub const RECEIVED:             u8 = 0;
pub const FINISH:               u8 = 1;
pub const RET_ERROR:            u8 = 2;
pub const KEM:                  u8 = 3;
pub const KDF:                  u8 = 4;
pub const AEAD:                 u8 = 5;
pub const PUBKEY:               u8 = 6;
pub const ENCKEY:               u8 = 7;
pub const CIPHERTEXT:           u8 = 8;
pub const ASSOCIATED_DATA:      u8 = 9;
pub const TAGBYTES:             u8 = 10;
pub const UTF8:                 u8 = 11;    
pub const UTF16:                u8 = 12;   
pub const BREAK_CONNECTION:     u8 = 99;  

pub const RECEIVED_M: [u8; 1] = [0 as u8];
pub const FINISHED_M: [u8; 1] = [1 as u8];
pub const BREAK_CONNECTION_M: [u8; 1] = [99 as u8];