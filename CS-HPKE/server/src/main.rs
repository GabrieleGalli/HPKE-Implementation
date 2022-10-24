mod codes;
mod ciphersuite;
mod agility;
mod data_pack_manager;
mod utils;
mod psk;

use core::panic;
use std:: { 
    str, 
    vec, 
    io:: { Read, Write, Error }, 
    net:: { TcpListener, TcpStream, SocketAddr } 
};
use rand::{ rngs::StdRng, SeedableRng };
use agility::{ KemAlg, KdfAlg, AeadAlg, AgilePublicKey, AgilePskBundle, AgileOpModeRTy, AgileOpModeR, agile_setup_receiver, AgileEncappedKey, AgileAeadCtxR };

fn send_pack(stream:&mut TcpStream, pack: &[u8], what: String) -> u8 {
    
    let mut buf = [1 as u8; 10]; 

    stream.write(pack).unwrap();
    println!("=> {} sent", what);

    match stream.read(&mut buf) {
        Ok(bytes_read) => {
            if bytes_read > 1 {
                panic!("send_pack :: some error in receiving a response, bytes read: {}", bytes_read);
            }
            if buf[0] == codes::RECEIVED { 
                println!("Client has received {}", what);
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
    if bytes_written == 0 { return Ok(()); }

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
    
    // ##### RECEPTION OF AVAILABLE CLIENT CIPHERSUITE #####

    let mut data = [0 as u8; 100]; 
    let mut kems = vec![];
    let mut kdfs = vec![];
    let mut aeads = vec![];

    loop {
        let bytes_read = stream.read(&mut data)?;
        if bytes_read == 0 {continue;}
        let id = data[data_pack_manager::ID_POS_HEADER];

        if id == codes::FINISH {
            println!("=> All client ciphersuite received\n");
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
    client_kems: &Vec<u16>, 
    client_kdfs: &Vec<u16>, 
    client_aeads: &Vec<u16>,
    supported_kems: &[KemAlg],
    supported_kdfs: &[KdfAlg],
    supported_aeads: &[AeadAlg]
) -> (KemAlg, KdfAlg, AeadAlg, bool) {

    // ##### CHOICE OF ALGORITHMS #####

    println!("=> Choosing the algorithms to be used...\n");

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
        println!("=> All algorithms have been choosen\n");
        _found_common_chipersuite = true;
    } else {
        stream.write(&codes::BREAK_CONNECTION_M).unwrap();
        panic!("choose_algorithms :: Insufficient common algorithms");
    }

    return (choosen_kem, choosen_kdf, choosen_aead, _found_common_chipersuite);
}


fn send_algorithms_pubkey_r(stream: &mut TcpStream, kem: KemAlg, kdf: KdfAlg, aead: AeadAlg, pubkey: AgilePublicKey) -> Result<(), Error> {

    // ##### SENDING THE CHOSEN ALGORITHMS TO THE CLIENT #####

    println!("=> Sending chosen algorithms...\n");
    
    let kem = kem.to_u16();
    let v_kem = utils::u16_to_vec_be(kem);
    let binding = data_pack_manager::pack_as_vect(v_kem, codes::UTF16, codes::KEM);
    let kem_pack = binding.as_slice();
    if send_pack(stream, kem_pack, String::from("KEM algorithm")) == codes::RET_ERROR { panic!("Failed to send packet") }

    let kdf = kdf.to_u16();
    let v_kdf = utils::u16_to_vec_be(kdf);
    let binding = data_pack_manager::pack_as_vect(v_kdf, codes::UTF16, codes::KDF);
    let kdf_pack = binding.as_slice();
    if send_pack(stream, kdf_pack, String::from("KDF algorithm")) == codes::RET_ERROR { panic!("Failed to send packet") }

    let aead = aead.to_u16();
    let v_aead = utils::u16_to_vec_be(aead);
    let binding = data_pack_manager::pack_as_vect(v_aead, codes::UTF16, codes::AEAD);
    let aead_pack = binding.as_slice();
    if send_pack(stream, aead_pack, String::from("AEAD algorithm")) == codes::RET_ERROR { panic!("Failed to send packet") }

    let pk = pubkey.pubkey_bytes;
    let binding = data_pack_manager::pack_as_vect(pk, codes::UTF8, codes::PUBKEY);
    let pk_pack = binding.as_slice();
    if send_pack(stream, pk_pack, String::from("Public Key")) == codes::RET_ERROR { panic!("Failed to send packet") }

    println!("=> Selected algorithms and public key sent\n");

    Ok(())

}

fn receive_pskid(mut stream: &TcpStream) -> Result<u8, Error> {
    let mut data = [0 as u8; 100];
    let mut out: Vec<u8> = vec![];
    loop {
        let bytes_read = stream.read(&mut data)?;
        if bytes_read == 0 { continue; }
        let id = data[data_pack_manager::ID_POS_HEADER];

        if id == codes::PSK_ID {
            println!("=> PSK_ID arrived");
            handle_data_u8(stream, &mut out, &data)?;
            if out.len() == 1 {
                return Ok(out[0]);
            }      
        }
    }
}

fn receive_enc(mut stream: &TcpStream, kem: &KemAlg) -> Result<(Vec<u8>, AgilePublicKey), Error> {
    let mut data = [0 as u8; 100];
    let mut enc: Vec<u8> = vec![];

    let mut enc_pass = false;
    let mut pk_pass = false;

    let mut client_pubkey = AgilePublicKey { kem_alg: *kem, pubkey_bytes: [0 as u8].to_vec() };

    loop {
        let bytes_read = stream.read(&mut data)?;
        if bytes_read == 0 {continue;}
        let id = data[data_pack_manager::ID_POS_HEADER];

        if id == codes::ENCKEY {
            println!("=> Encryption key arrived");
            handle_data_u8(stream, &mut enc, &data)?;  
            enc_pass = true;
        } else if id == codes::PUBKEY {
            println!("=> Client public key arrived");
            let mut tmp = vec![];
            handle_data_u8(stream, &mut tmp, &data)?;          
            client_pubkey = AgilePublicKey {
                kem_alg: *kem,
                pubkey_bytes: tmp,
            };
            pk_pass = true;
        }

        if enc_pass && pk_pass {
            return Ok((enc, client_pubkey));
        }
    }
}

fn client_exchange_mex(mut stream: &TcpStream, mut aead_ctx: Box<dyn AgileAeadCtxR>) -> Result<(), Error> {
    let mut ct:Vec<u8> = vec![]; 
    let mut ad:Vec<u8> = vec![];  

    let mut ct_pass = false;
    let mut ad_pass = false;

    let mut data = [0 as u8; 100]; 

    loop {

        let bytes_read = stream.read(&mut data)?;
        if bytes_read == 0 { return Ok(()); }
        let id = data[data_pack_manager::ID_POS_HEADER];
        
        if id == codes::CIPHERTEXT {
            handle_data_u8(stream, &mut ct, &data)?;
            ct_pass = true;
        } else if id == codes::ASSOCIATED_DATA {
            handle_data_u8(stream, &mut ad, &data)?;
            ad_pass = true;
        } else {
            panic!("client_exchange_mex :: wrong input");
        }

        if ct_pass && ad_pass {
            let ciphertext_copy = ct.clone();

            let plaintext = aead_ctx.open(ciphertext_copy.as_slice(), ad.as_slice()).unwrap();

            let msg = str::from_utf8(&plaintext).unwrap();
            println!("=> Plaintext: {}", msg);
            ct.clear();
            ad.clear();
            ct_pass = false;
            ad_pass = false;
        }
    }
}



fn main() {
    let info = b"Example session";

    // Supported Server Algorithms
    let supported_kem_algs = ciphersuite::supported_kem_algs();
    let supported_kdf_algs = ciphersuite::supported_kdf_algs();
    let supported_aead_algs = ciphersuite::supported_aead_algs();

    let remote: SocketAddr = "0.0.0.0:8888".parse().unwrap();
    let listener = TcpListener::bind(remote).expect("Could not bind");

    for stream in listener.incoming() {

        match stream {

            Ok(mut stream) => {

                println!("=> Incoming connection at port: {}\n", stream.peer_addr().unwrap());

                let (client_available_kems, client_available_kdfs, client_available_aeads) = handle_client(&stream).unwrap();

                let (kem, kdf, aead, common_ciphersuite_exist) = choose_algorithms(
                    &stream,
                    &client_available_kems,
                    &client_available_kdfs,
                    &client_available_aeads,
                    supported_kem_algs,
                    supported_kdf_algs,
                    supported_aead_algs
                );

                // Receiver key pair
                let mut csprng = StdRng::from_entropy();
                let server_keypair = agility::agile_gen_keypair(kem, &mut csprng);
                let server_publickey = server_keypair.1.clone();

                if common_ciphersuite_exist {
                    send_algorithms_pubkey_r(&mut stream, kem, kdf, aead, server_publickey).unwrap();
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

                // ##### ENC #####
                let (enc, client_publickey) = receive_enc(&stream, &kem).unwrap();
                let enc = AgileEncappedKey {
                    kem_alg: kem,
                    encapped_key_bytes: enc
                };

                // OpMODE
                let op_mode_r_ty = AgileOpModeRTy::AuthPsk(client_publickey, psk_bundle);
                let op_mode_r = AgileOpModeR {
                    kem_alg: kem,
                    op_mode_ty: op_mode_r_ty,
                };

                // receiver context
                let mut aead_ctx_r = agile_setup_receiver(
                    aead,
                    kdf,
                    kem,
                    &op_mode_r,
                    &server_keypair,
                    &enc,
                    &info[..],
                ).unwrap();

                client_exchange_mex(&stream, aead_ctx_r).unwrap();
                
            }
            Err(e) => { 
                eprintln!("Failed: {}", e) 
            }
        }
    }
    
}
