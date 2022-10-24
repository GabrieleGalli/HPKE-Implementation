use std::collections::HashMap;

use crate::agility::KdfAlg;

const PSK_HKDF_SHA256_1: [u8; 32] = [166,74,40,96,216,149,173,61,146,6,204,211,206,217,20,96,88,203,183,222,4,248,166,100,231,213,111,244,152,168,150,88];
const PSK_HKDF_SHA256_2: [u8; 32] = [136,221,141,112,173,179,212,5,89,128,70,242,63,232,89,89,98,144,3,158,239,50,19,189,232,225,167,140,117,46,66,246];
const PSK_HKDF_SHA256_3: [u8; 32] = [30,166,92,95,198,232,94,241,173,165,216,23,45,19,1,35,64,152,85,166,59,127,231,79,185,18,232,140,69,83,19,157];

const PSK_HKDF_SHA384_1: [u8; 48] = [219,157,14,183,113,255,170,71,85,145,107,169,103,228,25,65,11,222,86,212,66,42,85,200,109,83,94,70,5,171,231,60,162,181,139,6,232,208,60,178,69,92,47,118,227,69,76,252];
const PSK_HKDF_SHA384_2: [u8; 48] = [44,107,146,149,91,25,55,69,17,57,222,249,2,41,35,184,87,103,238,142,90,28,79,90,192,169,188,61,149,172,6,225,247,189,246,253,240,48,50,119,236,107,221,129,236,253,157,208];
const PSK_HKDF_SHA384_3: [u8; 48] = [136,112,24,242,85,165,212,135,90,251,55,118,212,123,131,122,126,76,249,198,178,180,61,145,127,97,170,230,94,25,144,242,184,132,51,20,183,41,200,42,188,37,247,243,225,95,216,221];

const PSK_HKDF_SHA512_1: [u8; 64] = [201,89,61,88,152,62,116,134,114,58,116,64,38,249,130,172,36,130,164,124,126,36,61,155,150,74,33,193,47,80,160,207,232,161,169,222,214,65,184,26,61,238,119,156,185,64,69,12,253,253,206,127,38,239,166,173,179,137,220,132,237,55,138,6];
const PSK_HKDF_SHA512_2: [u8; 64] = [66,106,62,93,90,233,58,252,51,18,185,36,85,163,173,86,244,26,72,85,205,36,157,144,92,29,40,235,246,45,13,210,230,138,166,223,44,198,183,58,18,71,51,39,84,33,49,178,192,102,153,112,188,53,222,68,210,150,50,249,102,158,218,53];
const PSK_HKDF_SHA512_3: [u8; 64] = [62,149,11,184,180,80,5,51,120,239,115,144,124,238,100,204,221,71,119,127,28,176,192,117,84,185,139,39,84,73,247,123,100,167,117,207,253,226,26,50,145,204,249,248,140,173,67,77,107,130,55,243,62,108,223,15,67,227,27,36,228,57,203,183];

pub fn hashmap_psk_hkdfsha256() -> HashMap<u8, [u8; 32]> {
    let mut psk_hkdfsha256: HashMap<u8, [u8; 32]> = HashMap::new();  
    psk_hkdfsha256.insert(1, PSK_HKDF_SHA256_1);
    psk_hkdfsha256.insert(2, PSK_HKDF_SHA256_2);
    psk_hkdfsha256.insert(3, PSK_HKDF_SHA256_3);
    psk_hkdfsha256
}

pub fn hashmap_psk_hkdfsha384() -> HashMap<u8, [u8; 48]> {
    let mut psk_hkdfsha384: HashMap<u8, [u8; 48]> = HashMap::new();  
    psk_hkdfsha384.insert(1, PSK_HKDF_SHA384_1);
    psk_hkdfsha384.insert(2, PSK_HKDF_SHA384_2);
    psk_hkdfsha384.insert(3, PSK_HKDF_SHA384_3);
    psk_hkdfsha384
}

pub fn hashmap_psk_hkdfsha512() -> HashMap<u8, [u8; 64]> {
    let mut psk_hkdfsha512: HashMap<u8, [u8; 64]> = HashMap::new();  
    psk_hkdfsha512.insert(1, PSK_HKDF_SHA512_1);
    psk_hkdfsha512.insert(2, PSK_HKDF_SHA512_2);
    psk_hkdfsha512.insert(3, PSK_HKDF_SHA512_3);
    psk_hkdfsha512
}

pub fn get_psk_from_id(id: &[u8], kdf: KdfAlg) -> Vec<u8> {  
    if id.len() > 1 {
        panic!("get_psk_from_id :: wrong arguments");
    }  
    let id = id[0];
    if kdf == KdfAlg::HkdfSha256 {
        let hkdfsha256 = hashmap_psk_hkdfsha256();
        let psk = hkdfsha256.get(&id).copied().expect("Any pre-shared key associated and this ID"); 
        return psk.to_vec();
    } else if kdf == KdfAlg::HkdfSha384 {
        let hkdfsha384 = hashmap_psk_hkdfsha384();
        let psk = hkdfsha384.get(&id).copied().expect("Any pre-shared key associated and this ID");
        return psk.to_vec();
    } else if kdf == KdfAlg::HkdfSha512 {
        let hkdfsha512 = hashmap_psk_hkdfsha512();
        let psk = hkdfsha512.get(&id).copied().expect("Any pre-shared key associated and this ID");
        return psk.to_vec();
    } else {
        panic!("Not available algorithm");
    }
}