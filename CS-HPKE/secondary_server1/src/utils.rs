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
    } else if i == codes::PSK {
        String::from("PSK")
    } else if i == codes::PSK_ID {
        String::from("PSK ID")
    } else if i == codes::ASSOCIATED_DATA {
        String::from("Associated Data")
    } else if i == codes::SECRET {
        String::from("Secret")
    } else if i == codes::SHSEC {
        String::from("Shared Secret")
    } else if i == codes::HELLO {
        String::from("Hello")
    } else {
        String::from("Unknown")
    }
}

pub fn print_buf(buf: &[u8], what: String) {
    print!("{}: ", what);
    for i in buf {
        print!("{} ",i);
    }
    println!("\n");
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
    println!("\nlen: {}\n", count);
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