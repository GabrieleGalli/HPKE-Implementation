mod codes;
mod utils;
mod agility;
mod data_pack_manager;

use core::time;
use std:: { 
    io:: { Write, Read, Error, self }, 
    net:: { TcpStream, SocketAddr }, vec, thread::{self}
};
use rand::{ rngs::StdRng, SeedableRng };
use agility::{ KemAlg, KdfAlg, AeadAlg, AgilePublicKey, AgilePskBundle, AgileEncappedKey };
use strobe_rs::Strobe;

use crate::agility::{AgileOpModeSTy, AgileOpModeS, AgileAeadCtxS, agile_setup_sender_secondary};

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
                //utils::display_pack(pack);
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
            //utils::display_pack(input_buf);
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
    let mut secret: Vec<u8> = vec![];
    let mut psk: Vec<u8> = vec![];
    let mut pskid: Vec<u8> = vec![];

    let mut kem_pass = false;
    let mut kdf_pass = false;
    let mut aead_pass = false;
    let mut secret_pass = false;
    let mut psk_pass = false;
    let mut pskid_pass = false;

    loop {
        let bytes_read = stream.read(&mut data)?;
        if bytes_read == 0 {continue;}
        let id = data[data_pack_manager::ID_POS_HEADER];

        if id == codes::BREAK_CONNECTION {
            panic!("get_algorithms :: Insufficient common algorithms");
        }
       
        if id == codes::KEM {
            println!("=> KEM arrived");
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
            println!("=> KDF arrived");
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
            println!("=> AEAD arrived");
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
        } else if id == codes::SHSEC {
            println!("=> SCK arrived");
            handle_data_u8(stream, &mut secret, &data)?;  
            secret_pass = true;
        } else if id == codes::PSK {
            println!("=>PSK arrived");
            handle_data_u8(stream, &mut psk, &data)?;  
            psk_pass = true;
        } else if id == codes::PSK_ID {
            println!("=>PSK_ID arrived");
            handle_data_u8(stream, &mut pskid, &data)?;  
            pskid_pass = true;
        }
        if kem_pass && kdf_pass && aead_pass && secret_pass && psk_pass && pskid_pass {
            return Ok((kem, kdf, aead, secret, psk, pskid));  
        }
    }
}

fn server_exchange_mex(stream: &mut TcpStream, mut ctx: Strobe) {
    
    loop {
        
        println!("\nInserisci testo");
        let mut input = String::new();
        io::stdin().read_line(&mut input).expect("Failed to read");
        unsafe {
            let msg = input.as_bytes_mut();
            ctx.send_enc(msg, false);
            
            let ct_pack = data_pack_manager::pack_as_vect(msg.to_vec(), codes::UTF8, codes::CIPHERTEXT);
            let ct = ct_pack.as_slice();
            if send_pack(stream, ct, String::from("Ciphertext")) == codes::RET_ERROR { panic!("Failed to send packet") }
        }
    }
}

fn main() {
    let info = b"Example session";
    let kem;
    let kdf;
    let aead;
    let enc: AgileEncappedKey;
    let psk;
    let psk_id;
    let psk_bundle: AgilePskBundle;
    let keypair;
    let public_key;
    let mut csprng = StdRng::from_entropy();

    let server_id = [2 as u8];
    let client_id = [13 as u8];
    
    let kri = b"kri";
    let tuple5 = b"5-tuple";
    
    let sck;
    let mut scsk: [u8; 32] = [0; 32];
    let mut sssk: [u8; 32] = [0; 32];

    let mut remote: SocketAddr = "127.0.0.1:8889".parse().unwrap();
    match TcpStream::connect(remote) {

        Ok(mut stream) => {
            (kem, kdf, aead, sck, psk, psk_id) = pc_req(&mut stream).unwrap();

            // Sender key pair
            keypair = agility::agile_gen_keypair(kem, &mut csprng);
            public_key = keypair.1.clone();

            psk_bundle = {
                AgilePskBundle(hpke::PskBundle {
                    psk: &psk,
                    psk_id: &psk_id,
                })
            };
        }
        Err(e) => {
            println!("Connection Failure: {}\n", e);
            return;
        },
    }

    thread::sleep(time::Duration::from_millis(3000));
    
    remote.set_port(8890);

    match TcpStream::connect(remote) {

        Ok(mut stream) => {

            println!("=> Connection to server at port: {}\n", remote);

            let hello = data_pack_manager::pack_as_vect(codes::SC_M.to_vec(), codes::UTF8, codes::HELLO);
            if send_pack(&mut stream, &hello, String::from("Connection + pubkey request")) == codes::RET_ERROR { panic!("Failed to send packet") }

            let mut data = [0 as u8; 100];
            let server_pubkey;

            loop {
                let bytes_read = stream.read(&mut data).unwrap();
                if bytes_read == 0 {continue;}
                let id = data[data_pack_manager::ID_POS_HEADER];

                if id == codes::BREAK_CONNECTION {
                    panic!("Connection refused");
                }

                if id == codes::PUBKEY {
                    println!("=> SS Public Key arrived");
                    let mut tmp = vec![];
                    handle_data_u8(&stream, &mut tmp, &data).unwrap();
                    server_pubkey = AgilePublicKey {
                        kem_alg: kem,
                        pubkey_bytes: tmp,
                    };
                    println!("=> Sending public key...\n"); 
                    let binding = data_pack_manager::pack_as_vect(public_key.pubkey_bytes, codes::UTF8, codes::PUBKEY);
                    let pk_pack = binding.as_slice();
                    if send_pack(&mut stream, pk_pack, String::from("SC public key")) == codes::RET_ERROR { panic!("Failed to send packet") }
                    break;
                }
            }

            // OpMODE
            let op_mode_s_ty = AgileOpModeSTy::AuthPsk(keypair.clone(), psk_bundle);
            let op_mode_s = AgileOpModeS {
                kem_alg: kem,
                op_mode_ty: op_mode_s_ty,
            };

            println!("=> SCK: ");
            utils::display_vect(&sck);

            (scsk, sssk) = generate_session_keys(&sck, kri, tuple5);
            
            let ctx = agile_setup_sender_secondary(
                kem,
                &op_mode_s,
                &server_pubkey,
                &scsk
            ).unwrap();

            server_exchange_mex(&mut stream, ctx);

        }
        Err(e) => {
            println!("Connection Failure: {}\n", e);
            return;
        },
    }
}

fn generate_session_keys(sck: &Vec<u8>, kri: &[u8], tuple5: &[u8]) -> ([u8; 32], [u8; 32]) {    
    let mut kri5tuple: [u8; 32] = [0; 32];
    concat_kdf::derive_key_into::<sha2::Sha256>(kri, tuple5, &mut kri5tuple).unwrap();
    utils::print_buf(kri5tuple.as_slice(), String::from("kri5tuple"));

    let mut scsk: [u8; 32] = [0; 32];
    concat_kdf::derive_key_into::<sha2::Sha256>(&kri5tuple, &sck, &mut scsk).unwrap();
    utils::print_buf(scsk.as_slice(), String::from("scsk"));

    let mut sssk: [u8; 32] = [0; 32];
    concat_kdf::derive_key_into::<sha2::Sha256>(&kri5tuple, &sck, &mut sssk).unwrap();
    utils::print_buf(sssk.as_slice(), String::from("sssk"));

    (scsk, sssk) 
}
