use crate::{data_pack_manager::{ID_POS_HEADER, DATA_START_POS, DATALEN_POS_HEADER}, codes};

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

// Printa il pacchetto completo
pub fn display_pack(pack: &[u8]) {
    let id = pack[ID_POS_HEADER];
    let dtype = int_to_datatype_display(id);
    print!("{}: ", dtype);
    let mut count:i8 = 0;
    for i in pack {
        count+=1;
        print!("{} ",i);
    }
    println!("\nlen: {}\n", count);
}

pub fn display_buf(buf: &[u8]) {
    print!("data: ");
    for i in buf { 
        print!("{} ", i); 
    }
    print!("\n\n");
}

// Rimpie il vettore con i dati dentro al buffer
pub fn buf_to_vect(vec: &mut Vec<u8>, buf: &[u8]) {
    let mut ii = DATA_START_POS;
    let pack_len = buf[DATALEN_POS_HEADER];

    if pack_len > 0 {
        loop {
            while ii <= ((pack_len + 1)).into() {
                vec.push(buf[ii]);
                ii += 1;
            }
            break;
        }
    } 
}