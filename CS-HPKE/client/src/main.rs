mod psk;
mod codes;
mod utils;
mod agility;
mod ciphersuite;
mod data_pack_manager;

use std:: { 
    io:: { Write, Read, Error, self }, 
    net:: { TcpListener, TcpStream, SocketAddr },
    vec
};
use rand::{ rngs::StdRng, SeedableRng };
use agility::{ KemAlg, KdfAlg, AeadAlg, AgilePublicKey, AgileEncappedKey };

use crate::agility::{AgileOpModeSTy, AgileOpModeS, AgilePskBundle, AgileAeadCtxS, agile_setup_sender_primary};

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

fn send_ciphersuite_s(stream: &mut TcpStream, supported_kem: &[KemAlg], supported_kdf: &[KdfAlg], supported_aead: &[AeadAlg]) -> Result<(), Error> {

    // ##### SENDING THE AVAILABLE CIPHERSUITE TO THE SERVER #####
    
    println!("=> Sending ciphersuite and public key request to the server\n"); 

    let mut v_kem = vec![];
    let mut v_kdf = vec![];
    let mut v_aead = vec![];

    // => KEM
    for a in supported_kem {
        let kem =  a.to_u16();
        let kem = kem.to_be_bytes();
        for k in kem {
            v_kem.push(k);
        }
    }
    let binding = data_pack_manager::pack_as_vect(
        v_kem,
        codes::UTF16,
        codes::KEM
    );
    let kem_pack = binding.as_slice();
    if send_pack(stream, kem_pack, String::from("KEM algorithms")) 
        == codes::RET_ERROR { panic!("Failed to send packet") }

    // => KDF
    for a in supported_kdf {
        let kdf =  a.to_u16();
        let kdf = kdf.to_be_bytes();
        for k in kdf {
            v_kdf.push(k); 
        }
    }
    let binding = data_pack_manager::pack_as_vect(v_kdf, codes::UTF16, codes::KDF);
    let kdf_pack = binding.as_slice();
    if send_pack(stream, kdf_pack, String::from("KDF algorithms")) == codes::RET_ERROR { panic!("Failed to send packet") }

    // => AEAD
    for a in supported_aead {
        let aead =  a.to_u16();
        let aead = aead.to_be_bytes();
        for k in aead {
            v_aead.push(k);
        }
    }
    let binding = data_pack_manager::pack_as_vect(v_aead, codes::UTF16, codes::AEAD);
    let aead_pack = binding.as_slice();
    if send_pack(stream, aead_pack, String::from("AEAD algorithms")) == codes::RET_ERROR { panic!("Failed to send packet") }

    //stream.write(&codes::FINISHED_M).unwrap();
    println!("=> Available ciphersuite sent to the server\n");
    Ok(())

}

fn handle_data_u8(mut stream: &TcpStream, output_vec: &mut Vec<u8>, input_buf: &[u8]) -> Result<(), Error> {
    let bytes_written = stream.write(&codes::RECEIVED_M)?;
    if bytes_written == 0 { return Ok(()); }

    let mut index = data_pack_manager::DATA_START_POS;
    let pack_len = input_buf[data_pack_manager::DATALEN_POS_HEADER];
    let protocol = input_buf[data_pack_manager::PROT_POS_HEADER];

    if pack_len > 0 {
        if protocol == codes::UTF8 {
            //utils::display_pack(input_buf);
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

fn get_algorithms(stream: &mut TcpStream) -> Result<(KemAlg, KdfAlg, AeadAlg, AgilePublicKey), Error> {

    // ##### RECEIVING THE ALGORITHMS CHOSEN BY THE SERVER #####

    let mut data = [0 as u8; 100];

    // Inizializzazioni 
    let mut kem: KemAlg = KemAlg::X25519HkdfSha256;
    let mut kdf: KdfAlg = KdfAlg::HkdfSha256;
    let mut aead: AeadAlg = AeadAlg::AesGcm128;
    let mut server_pubkey = AgilePublicKey { kem_alg: kem, pubkey_bytes: [0 as u8].to_vec() };

    // flag di avvenuta ricezione
    let mut kem_pass = false;
    let mut kdf_pass = false;
    let mut aead_pass = false;
    let mut pk_pass = false;

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
        }

        // => KDF
        if id == codes::KDF {
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
        }

        // => AEAD
        if id == codes::AEAD {
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
        }

        // => PUBLIC KEY
        if id == codes::PUBKEY {
            println!("=> Server Public Key arrived");
            let mut tmp = vec![];
            handle_data_u8(&stream, &mut tmp, &data)?;
            server_pubkey = AgilePublicKey {
                kem_alg: kem,
                pubkey_bytes: tmp,
            };
            pk_pass = true;
        }

        if kem_pass && kdf_pass && aead_pass && pk_pass {
            println!("=> Client received the algorithms to be used and the public key\n");
            return Ok((kem, kdf, aead, server_pubkey));  
        }
    }
    
}

fn send_pskid(stream: &mut TcpStream, kdf: &KdfAlg, psk_id: u8) -> Result<Vec<u8>, Error> {

    // ##### SENDING THE ID OF THE PSK TO BE USED TO THE SERVER #####
    
    println!("=> Sending pre-shared key ID to the server\n"); 
    let binding = data_pack_manager::pack_as_vect(vec![psk_id], codes::UTF8, codes::PSK_ID);
    let pskid_pack = binding.as_slice();
    if send_pack(stream, pskid_pack, String::from("PSK ID")) == codes::RET_ERROR { panic!("Failed to send packet") }
    Ok(psk::get_psk_from_id(psk_id, *kdf))
}

fn send_enc_pubkey(stream: &mut TcpStream, enc: AgileEncappedKey, pubkey: AgilePublicKey) -> Result<(), Error> {

    // ##### SENDING ENC + CLIENT_PUBKEY TO THE SERVER #####
    
    println!("=> Sending encryption key to the server\n"); 
    let binding = data_pack_manager::pack_as_vect(enc.encapped_key_bytes, codes::UTF8, codes::ENCKEY);
    let enc_pack = binding.as_slice();
    if send_pack(stream, enc_pack, String::from("Encryption key")) == codes::RET_ERROR { panic!("Failed to send packet") }

    println!("=> Sending public key to the server\n"); 
    let binding = data_pack_manager::pack_as_vect(pubkey.pubkey_bytes, codes::UTF8, codes::PUBKEY);
    let pk_pack = binding.as_slice();
    if send_pack(stream, pk_pack, String::from("Client public key")) == codes::RET_ERROR { panic!("Failed to send packet") }

    Ok(())
}

fn server_exchange_mex(stream: &mut TcpStream, mut aead_ctx: Box<dyn AgileAeadCtxS>) {
    let aad = b"all about that paper, boy";
    
    loop {
        
        println!("\nInserisci testo");
        let mut input = String::new();
        io::stdin().read_line(&mut input).expect("Failed to read");
        let msg = input.as_bytes();
        
        let ciphertext = aead_ctx.seal(msg, aad).unwrap();

        let ct_pack = data_pack_manager::pack_as_vect(ciphertext, codes::UTF8, codes::CIPHERTEXT);
        let ct = ct_pack.as_slice();
        if send_pack(stream, ct, String::from("Ciphertext")) == codes::RET_ERROR { panic!("Failed to send packet") }

        let ad_pack = data_pack_manager::pack_as_vect(aad.to_vec(), codes::UTF8, codes::ASSOCIATED_DATA);
        let ad = ad_pack.as_slice();
        if send_pack(stream, ad, String::from("AssociatedData")) == codes::RET_ERROR { panic!("Failed to send packet") }      
    }
}

fn main() {  
    let info = b"Example session";

    // Supported Client Algorithms
    let supported_kem_algs = ciphersuite::supported_kem_algs();
    let supported_kdf_algs = ciphersuite::supported_kdf_algs();
    let supported_aead_algs = ciphersuite::supported_aead_algs();

    let _kem;
    let _kdf;
    let _aead;
    let _enc;
    let _psk;
    let _pskid;
    let _shared_secret;

    let primary_server: SocketAddr = "127.0.0.1:8888".parse().unwrap();

    match TcpStream::connect(primary_server) {

        Ok(mut stream) => {

            println!("=> Connection to server at port: {}\n", primary_server);

            let hello = data_pack_manager::pack_as_vect(codes::PC_M.to_vec(), codes::UTF8, codes::HELLO);
            if send_pack(&mut stream, &hello, String::from("Connection request")) == codes::RET_ERROR { panic!("Failed to send packet") }

            send_ciphersuite_s(&mut stream, supported_kem_algs, supported_kdf_algs, supported_aead_algs).unwrap();
            
            let (kem, kdf, aead, server_publickey) = get_algorithms(&mut stream).unwrap();

            _kem = kem.clone();
            _kdf = kdf.clone();
            _aead = aead.clone();

            // Sender key pair
            let mut csprng = StdRng::from_entropy();
            let keypair = agility::agile_gen_keypair(kem, &mut csprng);
            let public_key = keypair.1.clone();

            // PSK bundle
            let psk_id = [3 as u8];
            let psk = send_pskid(&mut stream, &kdf, psk_id[0]).unwrap();

            _psk = psk.clone();
            _pskid = psk_id.clone();

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
            let (enc, shared_secret) = agile_setup_sender_primary(
                aead,
                kdf,
                kem,
                &op_mode_s,
                &server_publickey,
                &info[..],
                &mut csprng,
            ).unwrap();

            _enc = enc.clone();
            _shared_secret = shared_secret.clone();

            send_enc_pubkey(&mut stream, enc.clone(), public_key.clone()).unwrap();

            //server_exchange_mex(&mut stream, aead_ctx_s);
        }
        Err(e) => {
            println!("Connection Failure: {}\n", e);
            return;
        },
    }

    let socket_pc: SocketAddr = "0.0.0.0:8889".parse().unwrap();
    let listener = TcpListener::bind(socket_pc).expect("Could not bind");
    //let secondary_clients = vec![];
    

    for stream in listener.incoming() {

        match stream {

            Ok(mut stream) => {

                println!("=> Incoming connection at port: {}\n", stream.peer_addr().unwrap());
                
                let connection_type;
                let mut data = [0 as u8; 100]; 
                
                loop {
                    let bytes_read = stream.read(&mut data).unwrap();
                    if bytes_read == 0 {continue;}
                    let id = data[data_pack_manager::ID_POS_HEADER];

                    if id == codes::HELLO {
                        let mut tmp = vec![];
                        handle_data_u8(&stream, &mut tmp, &data).unwrap();
                        if tmp.len() == 1 {
                            if tmp[0] == codes::SC {
                                connection_type = codes::SC;
                                break;
                            } else if tmp[0] == codes::SS {
                                connection_type = codes::SS;
                                break;
                            }
                        }
                    }
                }

                if connection_type == codes::SC {
                    println!("connesso SC");
                    // => KEM
                    let kem =  _kem.to_u16();
                    let v_kem = utils::u16_to_vec_be(kem);
                    let binding = data_pack_manager::pack_as_vect(v_kem, codes::UTF16, codes::KEM);
                    let kem_pack = binding.as_slice();
                    if send_pack(&mut stream, kem_pack, String::from("KEM algorithm")) == codes::RET_ERROR { panic!("Failed to send packet") }
                
                    // => KDF
                    let kdf = _kdf.to_u16();
                    let v_kdf = utils::u16_to_vec_be(kdf);
                    let binding = data_pack_manager::pack_as_vect(v_kdf, codes::UTF16, codes::KDF);
                    let kdf_pack = binding.as_slice();
                    if send_pack(&mut stream, kdf_pack, String::from("KDF algorithm")) == codes::RET_ERROR { panic!("Failed to send packet") }

                    // => AEAD
                    let aead = _aead.to_u16();
                    let v_aead = utils::u16_to_vec_be(aead);
                    let binding = data_pack_manager::pack_as_vect(v_aead, codes::UTF16, codes::AEAD);
                    let aead_pack = binding.as_slice();
                    if send_pack(&mut stream, aead_pack, String::from("AEAD algorithm")) == codes::RET_ERROR { panic!("Failed to send packet") }

                    // => Shared Secret - SCK

                    let km = _shared_secret.clone();
                      // suppose of knowing Cliend_ID, Server_ID, Pair_ID
                      let _server_id = [2 as u8];
                      let client_id = [13 as u8];
                      let pair_id = [1 as u8];

                      let mut kdf_km_pairid: [u8; 32] = [0; 32];
                      concat_kdf::derive_key_into::<sha2::Sha256>(&km, &pair_id, &mut kdf_km_pairid).unwrap();
                      utils::print_buf(kdf_km_pairid.as_slice(), String::from("km_pairid"));
                  
                      let mut sck: [u8; 32] = [0; 32];
                      concat_kdf::derive_key_into::<sha2::Sha256>(&kdf_km_pairid, &client_id, &mut sck).unwrap();
                      utils::print_buf(sck.as_slice(), String::from("SCK"));

                    let binding = data_pack_manager::pack_as_vect(sck.to_vec(), codes::UTF8, codes::SHSEC);
                    let shse_pack = binding.as_slice();
                    if send_pack(&mut stream, shse_pack, String::from("SCK")) == codes::RET_ERROR { panic!("Failed to send packet") }
                    
                    /* PROVA COMUNICAZIONE CON SHARED SECRET NON DERIVATO CON KDF
                    let tmp = _shared_secret.clone();
                    let binding = data_pack_manager::pack_as_vect(tmp, codes::UTF8, codes::SHSEC);
                    let shse_pack = binding.as_slice();
                    if send_pack(&mut stream, shse_pack, String::from("SHSE")) == codes::RET_ERROR { panic!("Failed to send packet") }
                    */

                    // => PSK
                    let tmp = _psk.clone();
                    let binding = data_pack_manager::pack_as_vect(tmp, codes::UTF8, codes::PSK);
                    let psk_pack = binding.as_slice();
                    if send_pack(&mut stream, psk_pack, String::from("PSK")) == codes::RET_ERROR { panic!("Failed to send packet") }

                    // => PSK_ID
                    let binding = data_pack_manager::pack_as_vect(_pskid.to_vec(), codes::UTF8, codes::PSK_ID);
                    let pskid_pack = binding.as_slice();
                    if send_pack(&mut stream, pskid_pack, String::from("PSK_ID")) == codes::RET_ERROR { panic!("Failed to send packet") }
                }
            }
            
            Err(e) => { 
                eprintln!("Failed: {}", e) 
            }
        }
    }
}
