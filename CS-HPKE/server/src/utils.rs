use std::fmt::Display;

use crate::{data_pack_manager, codes};

// Rende un elemento di DataType printabile da un numero intero
pub fn int_to_datatype_display(i: u8) -> String {
    match i {
        codes::KEM => String::from("KEM"),
        codes::KDF => String::from("KDF"),
        codes::AEAD => String::from("AEAD"),
        codes::PUBKEY => String::from("PublicKey"),
        codes::ENCKEY => String::from("EncKey"),
        codes::CIPHERTEXT => String::from("CipherText"),
        codes::PSK => String::from("PSK"),
        codes::PSK_ID => String::from("PSK ID"),
        codes::ASSOCIATED_DATA => String::from("Associated Data"),
        codes::SECRET => String::from("Secret"), 
        codes::SHSEC => String::from("Shared Secret"), 
        codes::HELLO => String::from ("Hello"),
            _=>String::from ("Unknown") 
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
    println!("\nlen: {}\n", count);
}

pub fn print_buf(buf: &[u8], what: &str) {
    println!("{}: {:?}", what, buf);
}


pub fn display_vect<T: Display>(vect: &[T]) {
    println!("vect: {}", vect.iter().map(|x| x.to_string()).collect::<Vec<String>>().join(" "));
}

// converte un u16 in un vettore di u8
pub fn u16_to_vec_be(data: u16) -> Vec<u8> {
    data.to_be_bytes().to_vec()
}
