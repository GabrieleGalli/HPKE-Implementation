mod codes;
mod ciphersuite;
mod agility;
mod data_pack_manager;
mod utils;

use std::net:: { TcpStream, SocketAddr };
use std::{str, clone};
use std::io::{self, BufRead, BufReader, Write, Read, Error};
use std::time::Duration;

use agility::{KemAlg, KdfAlg, AeadAlg, AgilePublicKey, AgileEncappedKey};
use crate::data_pack_manager::{create_pack, ID_POS_HEADER};

fn send_pack(stream: &mut TcpStream, pack: &[u8], what: String) -> u8 {
    let mut buf = [1 as u8]; 

    stream.write(pack).unwrap();
    println!("{} inviata", what);

    match stream.read(&mut buf) {

        Ok(_) => {
            if buf == [codes::RECEIVED] { 
                println!("Il server ha ricevuto {}", what);
                return codes::RECEIVED;
            } else {
                return codes::RET_ERROR;
            }
        },
        Err(e) => {
            println!("Fallimento nel ricevere dati: {}", e);
            return codes::RET_ERROR;
        }
    }
}

fn send_ciphersuite(
    remote: SocketAddr, 
    stream: &mut TcpStream, 
    supported_kem: &[KemAlg], 
    supported_kdf: &[KdfAlg], 
    supported_aead: &[AeadAlg],
) -> Result<(), Error> {

    // ##### INVIO DELLA CIPHERSUITE DISPONIBILE AL SERVER #####
    
    println!("\nConnessione al server avviata alla porta {}", remote);
    println!("\nInvio ciphersuite e richiesta chiave pubblica al server\n"); 

    let mut tmp_v_kem = vec![];
    let mut tmp_v_kdf = vec![];
    let mut tmp_v_aead = vec![];

    // => KEM
    for a in supported_kem {
        let kem =  a.to_u8();
        tmp_v_kem.push(kem);
    }
    let kem_pack = create_pack(codes::KEM, tmp_v_kem);
    let kem_pack = kem_pack.group();
    let kem_pack = kem_pack.as_slice();
    if send_pack(stream, kem_pack, String::from("KEM algorithms")) == codes::RET_ERROR { panic!("Failed to send packet") }
    utils::display_pack(kem_pack);

    // => KDF
    for a in supported_kdf {
        let kdf =  a.to_u8();
        tmp_v_kdf.push(kdf);
    }
    let kdf_pack = create_pack(codes::KDF, tmp_v_kdf);
    let kdf_pack = kdf_pack.group();
    let kdf_pack = kdf_pack.as_slice();
    if send_pack(stream, kdf_pack, String::from("KDF algorithms")) == codes::RET_ERROR { panic!("Failed to send packet") }
    utils::display_pack(kdf_pack);

    // => AEAD
    for a in supported_aead {
        let aead =  a.to_u8();
        tmp_v_aead.push(aead);
    }
    let aead_pack = create_pack(codes::AEAD, tmp_v_aead);
    let aead_pack = aead_pack.group();
    let aead_pack = aead_pack.as_slice();
    if send_pack(stream, aead_pack, String::from("AEAD algorithms")) == codes::RET_ERROR { panic!("Failed to send packet") }
    utils::display_pack(aead_pack);

    stream.write(&codes::FINISHED_M).unwrap();
    println!("\nCiphersuite disponibile inviata al server\n");
    Ok(())

}

fn get_algorithms(stream: &mut TcpStream) -> Result<(KemAlg, KdfAlg, AeadAlg, AgilePublicKey), Error> {

    // ##### RICEZIONE DEGLI ALGORITMI SCELTI DAL SERVER #####

    let mut data = [0 as u8; 100];

    // Inizializzazioni 
    let mut kem: KemAlg = KemAlg::X25519HkdfSha256;
    let mut kdf: KdfAlg = KdfAlg::HkdfSha256;
    let mut aead: AeadAlg = AeadAlg::AesGcm128;
    let mut server_pubkey = AgilePublicKey { 
        kem_alg: kem, 
        pubkey_bytes: [0 as u8].to_vec()
    };

    // flag di avvenuta ricezione
    let mut kem_pass = false;
    let mut kdf_pass = false;
    let mut aead_pass = false;
    let mut pk_pass = false;

    loop {
        let bytes_read = stream.read(&mut data)?;
        if bytes_read == 0 {continue;}

        // => KEM
        if data[ID_POS_HEADER] == codes::KEM {
            println!("Arrivato kem scelto dal server");
            stream.write(&codes::RECEIVED_M)?;
            utils::display_buf(&data);
            if data [2] == agility::KemAlg::X25519HkdfSha256.to_u8() {
                kem = agility::KemAlg::X25519HkdfSha256;
                kem_pass = true;
            } else if data [2] == agility::KemAlg::DhP256HkdfSha256.to_u8() {
                kem = agility::KemAlg::DhP256HkdfSha256;
                kem_pass = true;
            } else {
                panic!("Nessun algoritmo kem compatibile\n")
            }
        }

        // => KDF
        if data[ID_POS_HEADER] == codes::KDF {
            println!("Arrivato kdf scelto dal server");
            stream.write(&codes::RECEIVED_M)?;
            utils::display_buf(&data);
            if data [2] == agility::KdfAlg::HkdfSha256.to_u8() {
                kdf = agility::KdfAlg::HkdfSha256;
                kdf_pass = true;
            } else if data [2] == agility::KdfAlg::HkdfSha384.to_u8() {
                kdf = agility::KdfAlg::HkdfSha384;
                kdf_pass = true;
            } else if data [2] == agility::KdfAlg::HkdfSha512.to_u8() {
                kdf = agility::KdfAlg::HkdfSha512;
                kdf_pass = true;
            } else {
                panic!("Nessun algoritmo kem compatibile")
            }
        }

        // => AEAD
        if data[ID_POS_HEADER] == codes::AEAD {
            println!("Arrivato aead scelto dal server");
            stream.write(&codes::RECEIVED_M)?;
            utils::display_buf(&data);
            if data [2] == agility::AeadAlg::AesGcm128.to_u8() {
                aead = agility::AeadAlg::AesGcm128;
                aead_pass = true;
            } else if data [2] == agility::AeadAlg::AesGcm256.to_u8() {
                aead = agility::AeadAlg::AesGcm256;
                aead_pass = true;
            } else if data [2] == agility::AeadAlg::ChaCha20Poly1305.to_u8() {
                aead = agility::AeadAlg::ChaCha20Poly1305;
                aead_pass = true;
            } else {
                panic!("Nessun algoritmo kem compatibile")
            }
        }

        // => PUBLIC KEY
        if data[ID_POS_HEADER] == codes::PUBKEY {
            println!("Arrivata public key server");
            let mut tmp: Vec<u8> = [].to_vec();
            stream.write(&codes::RECEIVED_M)?;
            utils::display_buf(&data);
            utils::buf_to_vect(&mut tmp, &data);
            server_pubkey = AgilePublicKey {
                kem_alg: kem,
                pubkey_bytes: tmp,
            };
            pk_pass = true;
        }


        if kem_pass && kdf_pass && aead_pass && pk_pass {
            println!("Client ha ricevuto gli algoritmi da usare e la chiave pubblica\n");
            return Ok((kem, kdf, aead, server_pubkey));  
        }
    }
    
}

/*
fn server_exchange_msg(stream: &mut TcpStream, associated_data: &[u8], server_pk: &AgilePublicKey) {

    loop {
        println!("\nInserisci testo");
        let mut input = String::new();
        io::stdin().read_line(&mut input).expect("Failed to read");

        let (encapped_key, ciphertext, tag) =   
            client_encrypt_msg(
                input.as_bytes(), 
                associated_data, 
                &server_pk
            );
    }
}*/


fn main() {
    // algoritmi supportati dal server
    let supported_kem_algs = ciphersuite::supported_kem_algs();
    let supported_kdf_algs = ciphersuite::supported_kdf_algs();
    let supported_aead_algs = ciphersuite::supported_aead_algs();

    // Inizializzazioni
    let mut kem = agility::KemAlg::X25519HkdfSha256;
    let mut kdf = agility::KdfAlg::HkdfSha256;
    let mut aead = agility::AeadAlg::AesGcm128;
    let spk;

    let remote: SocketAddr = "127.0.0.1:8888".parse().unwrap();

    match TcpStream::connect(remote) {

        Ok(mut stream) => {
            send_ciphersuite(
                remote,
                &mut stream,
                supported_kem_algs,
                supported_kdf_algs,
                supported_aead_algs
            ).unwrap();
            
            (kem, kdf, aead, spk) = get_algorithms(&mut stream).unwrap();

            let y = 200;

            
        }
        Err(e) => {
            println!("Fallimento nel connettersi: {}\n", e);
            return;
        },
    }
}
