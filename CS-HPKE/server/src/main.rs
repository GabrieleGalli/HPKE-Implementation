mod codes;
mod ciphersuite;
mod agility;
mod data_pack_manager;
mod utils;
mod psk;

use core::panic;
use std:: { str, vec, io::{ Read, Write, Error }, net::{ TcpListener, TcpStream, SocketAddr } };
use codes::RECEIVED_M;
use rand::{ rngs::StdRng, SeedableRng };
use agility::{ KemAlg, KdfAlg, AeadAlg, AgilePublicKey, AgilePskBundle, AgileOpModeRTy, AgileOpModeR, agile_setup_receiver, AgileEncappedKey };

fn send_pack(stream:&mut TcpStream, pack: &[u8], what: String) -> u8 {
    
    let mut buf = [1 as u8; 10]; 

    stream.write(pack).unwrap();
    println!("{} sent", what);

    match stream.read(&mut buf) {
        Ok(bytes_read) => {
            if bytes_read > 1 {
                println!("bytes read: {}", bytes_read);
                panic!("send_pack :: some error in receiving a response");
            }
            if buf[0] == codes::RECEIVED { 
                println!("Server has received {}", what);
                return codes::RECEIVED;
            } else {
                return codes::RET_ERROR;
            }
        },
        Err(e) => {
            panic!("send_pack ::{}", e);
        }
    }
}

fn handle_data_u8(mut stream: &TcpStream, output_vec: &mut Vec<u8>, input_buf: &[u8]) -> Result<(), Error> {
    let bytes_written = stream.write(&codes::RECEIVED_M)?;
    if bytes_written == 0 {return Ok(());}

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
        } else { panic!("handle_data_u8 :: wrong arguments"); }
    } else { panic!("handle_data_u8 :: payload inesistente"); }

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
        } else { panic!("handle_data_u16 :: wrong arguments"); }
    } else { panic!("handle_data_u16 :: non-existing payload"); }

    utils::display_vect(output_vec);
    Ok(())
}


fn handle_client(mut stream: &TcpStream) -> Result<(Vec<u16>, Vec<u16>, Vec<u16>), Error> {
    
    // ##### RICEZIONE DELLA CIPHERSUITE DISPONIBILE DEL CLIENT #####

    let mut data = [0 as u8; 100]; 
    let mut kems = vec![];
    let mut kdfs = vec![];
    let mut aeads = vec![];

    loop {
        let bytes_read = stream.read(&mut data)?;
        if bytes_read == 0 {continue;}
        let id = data[data_pack_manager::ID_POS_HEADER];

        if id == codes::FINISH {
            println!("Ricevuta tutta la ciphersuite del client\n");
            break;
        } else if id == codes::KEM {
            handle_data_u16(stream, &mut kems, &data)?;
        } else if id == codes::KDF {
            handle_data_u16(stream, &mut kdfs, &data)?;
        } else if id == codes::AEAD {
            handle_data_u16(stream, &mut aeads, &data)?;
        }
    }

    Ok((kems, kdfs, aeads))
}

// Sceglie il primo algoritmo in comune che trova per ogni tipo 
fn choose_algorithms(
    mut stream: &TcpStream,
    client_kems: &mut Vec<u16>, 
    client_kdfs: &mut Vec<u16>, 
    client_aeads: &mut Vec<u16>,
    supported_kems: &[KemAlg],
    supported_kdfs: &[KdfAlg],
    supported_aeads: &[AeadAlg]
) -> (KemAlg, KdfAlg, AeadAlg, bool) {

    // ##### SCELTA DEGLI ALGORITMI #####

    println!("Scelgo gli algoritmi da usare...\n");

    let mut choosen_kem = KemAlg::DhP256HkdfSha256;
    let mut choosen_kdf = KdfAlg::HkdfSha384;
    let mut choosen_aead = AeadAlg::ChaCha20Poly1305;

    let mut kem_pass = false;
    let mut kdf_pass = false;
    let mut aead_pass = false;
    let mut _found_common_chipersuite = false;

    // => KEM
    for ckem in client_kems {
        let ckem_alg = agility::KemAlg::try_from_u16(*ckem).unwrap();
        for skem in supported_kems {
            if ckem_alg == *skem {
                choosen_kem = ckem_alg;
                kem_pass = true;
            }
        }
    }

    // => KDF
    for ckdf in client_kdfs {
        let ckdf_alg = agility::KdfAlg::try_from_u16(*ckdf).unwrap();
        for skdf in supported_kdfs {
            if ckdf_alg == *skdf {
                choosen_kdf = ckdf_alg;
                kdf_pass = true;
            }
        }
    }

    // => AEAD
    for caead in client_aeads {
        let caead_alg = agility::AeadAlg::try_from_u16(*caead).unwrap();
        for saead in supported_aeads {
            if caead_alg == *saead {
                choosen_aead = caead_alg;
                aead_pass = true;
            }
        }
    }

    if kem_pass && kdf_pass && aead_pass {
        println!("All algorithms have been choosen\n");
        _found_common_chipersuite = true;
    } else {
        stream.write(&codes::BREAK_CONNECTION_M).unwrap();
        panic!("choose_algorithms :: Insufficient common algorithms");
    }

    return (choosen_kem, choosen_kdf, choosen_aead, _found_common_chipersuite);

}


fn send_algorithms_and_pubkey (stream: &mut TcpStream, kem: KemAlg, kdf: KdfAlg, aead: AeadAlg, pubkey: AgilePublicKey) -> Result<(), Error> {

    // ##### INVIO AL CLIENT GLI ALGORITMI SCELTI #####

    println!("Invio gli algoritmi scelti...\n");
    
    let kem = kem.to_u16();
    let v_kem = utils::u16_to_vec_be(kem);
    let binding = data_pack_manager::pack_as_vect(v_kem, codes::UTF16, codes::KEM);
    let kem_pack = binding.as_slice();
    if send_pack(stream, kem_pack, String::from("KEM algorithm")) == codes::RET_ERROR { panic!("Failed to send packet") }
    utils::display_pack(kem_pack);

    let kdf = kdf.to_u16();
    let v_kdf = utils::u16_to_vec_be(kdf);
    let binding = data_pack_manager::pack_as_vect(v_kdf, codes::UTF16, codes::KDF);
    let kdf_pack = binding.as_slice();
    if send_pack(stream, kdf_pack, String::from("KDF algorithm")) == codes::RET_ERROR { panic!("Failed to send packet") }
    utils::display_pack(&kdf_pack);

    let aead = aead.to_u16();
    let v_aead = utils::u16_to_vec_be(aead);
    let binding = data_pack_manager::pack_as_vect(v_aead, codes::UTF16, codes::AEAD);
    let aead_pack = binding.as_slice();
    if send_pack(stream, aead_pack, String::from("AEAD algorithm")) == codes::RET_ERROR { panic!("Failed to send packet") }
    utils::display_pack(aead_pack);

    let pk = pubkey.pubkey_bytes;
    let binding = data_pack_manager::pack_as_vect(pk, codes::UTF8, codes::PUBKEY);
    let pk_pack = binding.as_slice();
    if send_pack(stream, pk_pack, String::from("Public Key")) == codes::RET_ERROR { panic!("Failed to send packet") }
    utils::display_pack(pk_pack);

    //stream.write(&codes::FINISHED_M).unwrap();
    println!("Inviati gli algoritmi scelti e la chiave pubblica\n");

    Ok(())

}

fn receive_pskid(mut stream: &TcpStream) -> Result<u8, Error> {
    let mut data = [0 as u8; 100];
    let mut out: Vec<u8> = vec![];
    loop {
        let bytes_read = stream.read(&mut data)?;
        if bytes_read == 0 {continue;}
        let id = data[data_pack_manager::ID_POS_HEADER];

        if id == codes::PSK_ID {
            println!("id arrivato");
            handle_data_u8(stream, &mut out, &data)?;
            if out.len() == 1 {
                return Ok(out[0]);
            }
            
        }
    }
}

fn receive_enc(mut stream: &TcpStream) -> Result<Vec<u8>, Error> {
    let mut data = [0 as u8; 100];
    let mut out: Vec<u8> = vec![];
    loop {
        let bytes_read = stream.read(&mut data)?;
        if bytes_read == 0 {continue;}
        let id = data[data_pack_manager::ID_POS_HEADER];

        if id == codes::ENCKEY {
            println!("enc arrivato");
            handle_data_u8(stream, &mut out, &data)?;
            return Ok(out);           
        }
    }
}

fn receive_cps(mut stream: &TcpStream) -> Result<Vec<u8>, Error> {
    let mut data = [0 as u8; 100];
    let mut out: Vec<u8> = vec![];
    loop {
        let bytes_read = stream.read(&mut data)?;
        if bytes_read == 0 {continue;}
        let id = data[data_pack_manager::ID_POS_HEADER];

        if id == codes::CIPHERTEXT {
            println!("ciphertext arrivato");
            handle_data_u8(stream, &mut out, &data)?;
            return Ok(out);           
        }
    }
}

fn main() {
    let info = b"Example session";

    // algoritmi supportati dal server
    let supported_kem_algs = ciphersuite::supported_kem_algs();
    let supported_kdf_algs = ciphersuite::supported_kdf_algs();
    let supported_aead_algs = ciphersuite::supported_aead_algs();

    // serve solo per averli inizializzati
    let mut kem = agility::KemAlg::X25519HkdfSha256;
    let mut kdf = agility::KdfAlg::HkdfSha256;
    let mut aead = agility::AeadAlg::AesGcm128;

    // Algoritmi del client
    let mut client_av_kems = vec![];
    let mut client_av_kdfs = vec![];
    let mut client_av_aeads = vec![];

    let mut common_cps_exist: bool;
    
    let remote: SocketAddr = "0.0.0.0:8888".parse().unwrap();
    let listener = TcpListener::bind(remote).expect("Could not bind");

    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                (client_av_kems, client_av_kdfs, client_av_aeads) = handle_client(&stream).unwrap();

                (kem, kdf, aead, common_cps_exist) = choose_algorithms(
                    &stream,
                    &mut client_av_kems,
                    &mut client_av_kdfs,
                    &mut client_av_aeads,
                    supported_kem_algs,
                    supported_kdf_algs,
                    supported_aead_algs
                );

                // Receiver key pair
                let mut csprng = StdRng::from_entropy();
                let server_keypair = agility::agile_gen_keypair(kem, &mut csprng);
                let public_key = server_keypair.1.clone();

                if common_cps_exist {
                    send_algorithms_and_pubkey(&mut stream, kem, kdf, aead, public_key).unwrap();
                } else {
                    panic!("main :: No common algorithms")
                }

                // PSK bundle
                let psk_id = receive_pskid(&stream).unwrap();
                let psk_id = [psk_id];
                let psk = psk::get_psk_from_id(&psk_id, kdf);
                let psk_bundle = {
                    AgilePskBundle(hpke::PskBundle {
                        psk: &psk,
                        psk_id: &psk_id,
                    })
                };

                // OpMODE
                let op_mode_r_ty = AgileOpModeRTy::AuthPsk(server_keypair.1.clone(), psk_bundle);
                let op_mode_r = AgileOpModeR {
                    kem_alg: kem,
                    op_mode_ty: op_mode_r_ty,
                };

                // ##### ENC #####
                let enc = receive_enc(&stream).unwrap();
                let enc = AgileEncappedKey {
                    kem_alg: kem,
                    encapped_key_bytes: enc
                };
                utils::print_buf(&enc.encapped_key_bytes, String::from("enc"));
                // receiver context
                let mut aead_ctx_r = agile_setup_receiver(
                    aead,
                    kdf,
                    kem,
                    &op_mode_r,
                    &server_keypair,
                    &enc,
                    &info[..],
                )
                .unwrap();

                let msg = receive_cps(&stream).unwrap();
                println!("{}", str::from_utf8(&msg).unwrap());
                
            }
            Err(e) => { 
                eprintln!("failed: {}", e) 
            }
        }
    }

}
