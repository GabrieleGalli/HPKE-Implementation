use std::fmt::Display;

use crate::{data_pack_manager, codes};

// Rende un elemento di DataType printabile da un numero intero
pub fn int_to_datatype_display(i: u8) -> String {
    if i == codes::KEM {
        String::from("KEM")
    } else if i == codes::KDF {
        String::from("KDF")
    } else if i == codes::AEAD {
        String::from("AEAD")
    } else if i == codes::PUBKEY {
        String::from("PublicKey")
    } else if i == codes::ENCKEY {
        String::from("EncKey")
    } else if i == codes::CIPHERTEXT {
        String::from("CipherText")
    } else {
        String::from("Unknown")
    }
}

// Printa il pacchetto completo u8
pub fn display_pack(pack: &[u8]) {
    let id = pack[data_pack_manager::ID_POS_HEADER];
    let dtype = int_to_datatype_display(id);
    print!("pack {}: ", dtype);
    let mut count = 0;
    for i in pack {
        count += 1;
        print!("{} ",i);
    }
    println!("\nlen: {}\n\n", count);
}

pub fn display_vect<T>(vect: &Vec<T>) 
where T: Display {
    print!("vect: ");
    for i in vect { 
        print!("{} ", i); 
    }
    print!("\n\n");
}

// converte un u16 in un vettore di u8
pub fn u16_to_vec_be(data: u16) -> Vec<u8> {
    let mut vect = vec![];
    let tmp = data.to_be_bytes();
    for k in tmp {
        vect.push(k);
    }
    vect
}