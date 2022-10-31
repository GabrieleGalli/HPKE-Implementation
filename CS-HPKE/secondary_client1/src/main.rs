mod codes;
mod utils;
mod agility;
mod data_pack_manager;

use std:: { 
    io:: { Write, Read, Error, self }, 
    net:: { TcpStream, SocketAddr },
    str, vec
};
use rand::{ rngs::StdRng, SeedableRng };
use agility::{ KemAlg, KdfAlg, AeadAlg, AgilePublicKey, AgilePskBundle, AgileEncappedKey, AgileAeadCtxR };

use crate::agility::{AgileOpModeSTy, AgileOpModeS, agile_setup_sender, AgileAeadCtxS};

fn send_pack(stream: &mut TcpStream, pack: &[u8], what: String) -> u8 {

    let mut buf = [1 as u8; 10]; 

    stream.write(pack).unwrap();
    println!("=> {} sent", what);
   
    match stream.read(&mut buf) {
        Ok(bytes_read) => {
            if bytes_read > 1 {
                panic!("send_pack :: some error in receiving a response, bytes read: {}", bytes_read);
            }
            if buf[0] == codes::RECEIVED { 
                println!("Receiver has received {}", what);
                utils::display_pack(pack);
                return codes::RECEIVED;
            } else {
                return codes::RET_ERROR;
            }    
        },
        Err(e) => {
            panic!("send_pack :: {}", e);
        }
    }

}

fn handle_data_u8(mut stream: &TcpStream, output_vec: &mut Vec<u8>, input_buf: &[u8]) -> Result<(), Error> {
    let bytes_written = stream.write(&codes::RECEIVED_M)?;
    if bytes_written == 0 { return Ok(()); }

    let mut index = data_pack_manager::DATA_START_POS;
    let pack_len = input_buf[data_pack_manager::DATALEN_POS_HEADER];
    let protocol = input_buf[data_pack_manager::PROT_POS_HEADER];

    if pack_len > 0 {
        if protocol == codes::UTF8 {
            utils::display_pack(input_buf);
            loop {
                while index <= ((pack_len + data_pack_manager::DATA_START_POS_U8 - 1)).into() {
                    output_vec.push(input_buf[index]);
                    index += 1;
                }
                break;
            }
        } else { panic!("handle_data_u8 :: Wrong arguments"); }
    } else { panic!("handle_data_u8 :: Payload inesistente"); }

    utils::display_vect(output_vec);
    Ok(())
}


fn handle_data_u16(mut stream: &TcpStream, output_vec: &mut Vec<u16>, input_buf: &[u8]) -> Result<(), Error> {
    let bytes_written = stream.write(&codes::RECEIVED_M)?;
    if bytes_written == 0 {return Ok(());}

    let mut index = data_pack_manager::DATA_START_POS;
    let pack_len = input_buf[data_pack_manager::DATALEN_POS_HEADER];
    let protocol = input_buf[data_pack_manager::PROT_POS_HEADER];

    if pack_len > 0 {
        if protocol == codes::UTF16 {
            utils::display_pack(input_buf);
            loop {
                while index <= ((pack_len + data_pack_manager::DATA_START_POS_U8 - 1)).into() {
                    let data = [input_buf[index], input_buf[index+1]];
                    let be_data = u16::from_be_bytes(data);
                    output_vec.push(be_data);
                    index += 2;
                }
                break;
            }
        } else { panic!("handle_data_u16 :: Wrong arguments"); }
    } else { panic!("handle_data_u16 :: Payload inesistente"); }

    utils::display_vect(output_vec);
    Ok(())
}

fn pc_req(stream: &mut TcpStream) -> Result<(KemAlg, KdfAlg, AeadAlg, Vec<u8>, Vec<u8>, Vec<u8>), Error> {
    let hello = data_pack_manager::pack_as_vect(codes::SC_M.to_vec(), codes::UTF8, codes::HELLO);
    if send_pack(stream, &hello, String::from("Connection request")) == codes::RET_ERROR { panic!("Failed to send packet") }
    
    let mut data = [0 as u8; 100];
    let mut kem: KemAlg = KemAlg::X25519HkdfSha256;
    let mut kdf: KdfAlg = KdfAlg::HkdfSha256;
    let mut aead: AeadAlg = AeadAlg::AesGcm128;
    let mut enc: Vec<u8> = vec![];
    let mut psk: Vec<u8> = vec![];
    let mut pskid: Vec<u8> = vec![];

    let mut kem_pass = false;
    let mut kdf_pass = false;
    let mut aead_pass = false;
    let mut enc_pass = false;
    let mut psk_pass = false;
    let mut pskid_pass = false;

    loop {
        let bytes_read = stream.read(&mut data)?;
        if bytes_read == 0 {continue;}
        let id = data[data_pack_manager::ID_POS_HEADER];

        if id == codes::BREAK_CONNECTION {
            panic!("get_algorithms :: Insufficient common algorithms");
        }
       
        // => KEM
        if id == codes::KEM {
            println!("=> Server-selected KEM arrived");
            let mut tmp = vec![];
            handle_data_u16(&stream, &mut tmp, &data)?;
            if tmp[0] == agility::KemAlg::X25519HkdfSha256.to_u16() {
                kem = agility::KemAlg::X25519HkdfSha256;
                kem_pass = true;
            } else if tmp[0] == agility::KemAlg::DhP256HkdfSha256.to_u16() {
                kem = agility::KemAlg::DhP256HkdfSha256;
                kem_pass = true;
            } else {
                panic!("No KEM compatible algorithm\n")
            }
        } else if id == codes::KDF {
            println!("=> Server-selected KDF arrived");
            let mut tmp = vec![];
            handle_data_u16(&stream, &mut tmp, &data)?;
            if tmp[0] == agility::KdfAlg::HkdfSha256.to_u16() {
                kdf = agility::KdfAlg::HkdfSha256;
                kdf_pass = true;
            } else if tmp[0] == agility::KdfAlg::HkdfSha384.to_u16() {
                kdf = agility::KdfAlg::HkdfSha384;
                kdf_pass = true;
            } else if tmp[0] == agility::KdfAlg::HkdfSha512.to_u16() {
                kdf = agility::KdfAlg::HkdfSha512;
                kdf_pass = true;
            } else {
                panic!("No KDF compatible algorithm")
            }
        } else if id == codes::AEAD {
            println!("=> Server-selected AEAD arrived");
            let mut tmp = vec![];
            handle_data_u16(&stream, &mut tmp, &data)?;
            if tmp[0] == agility::AeadAlg::AesGcm128.to_u16() {
                aead = agility::AeadAlg::AesGcm128;
                aead_pass = true;
            } else if tmp[0] == agility::AeadAlg::AesGcm256.to_u16() {
                aead = agility::AeadAlg::AesGcm256;
                aead_pass = true;
            } else if tmp[0] == agility::AeadAlg::ChaCha20Poly1305.to_u16() {
                aead = agility::AeadAlg::ChaCha20Poly1305;
                aead_pass = true;
            } else {
                panic!("No AEAD compatible algorithm")
            }
        } else if id == codes::ENCKEY {
            println!("=> Encryption key arrived");
            handle_data_u8(stream, &mut enc, &data)?;  
            enc_pass = true;
        } else if id == codes::PSK {
            println!("=>PSK arrived");
            handle_data_u8(stream, &mut psk, &data)?;  
            psk_pass = true;
        } else if id == codes::PSK_ID {
            println!("=>PSK_ID arrived");
            handle_data_u8(stream, &mut pskid, &data)?;  
            pskid_pass = true;
        }
        if kem_pass && kdf_pass && aead_pass && enc_pass && psk_pass && pskid_pass {
            println!("=>fff\n");
            return Ok((kem, kdf, aead, enc, psk, pskid));  
        }
    }

}

fn main() {
    let info = b"Example session";

    let primary_client: SocketAddr = "127.0.0.1:8889".parse().unwrap();
    //let secondary_server: SocketAddr = "127.0.0.1.8890".parse().unwrap();

    let kem;
    let kdf;
    let aead;
    let enc;
    let psk;
    let psk_id;

    match TcpStream::connect(primary_client) {

        Ok(mut stream) => {

            (kem, kdf, aead, enc, psk, psk_id) = pc_req(&mut stream).unwrap();

            // Sender key pair
            let mut csprng = StdRng::from_entropy();
            let keypair = agility::agile_gen_keypair(kem, &mut csprng);
            let public_key = keypair.1.clone();

            let psk_bundle = {
                AgilePskBundle(hpke::PskBundle {
                    psk: &psk,
                    psk_id: &psk_id,
                })
            };

            // OpMODE
            let op_mode_s_ty = AgileOpModeSTy::AuthPsk(keypair.clone(), psk_bundle);
            let op_mode_s = AgileOpModeS {
                kem_alg: kem,
                op_mode_ty: op_mode_s_ty,
            };

            // ##### ENC ##### + sender context
            let (enc, aead_ctx_s) = agile_setup_sender(
                aead,
                kdf,
                kem,
                &op_mode_s,
                &server_publickey,
                &info[..],
                &mut csprng,
            ).unwrap();
        }
        Err(e) => {
            println!("Connection Failure: {}\n", e);
            return;
        },
    }
}
