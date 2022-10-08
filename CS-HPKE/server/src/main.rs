use std::net::{TcpListener, TcpStream, Shutdown};
use std::net::SocketAddr;
use std::io::{Read, Write, Error, BufReader};

use hpke::generic_array::typenum::Len;
use hpke::{
    aead::{AeadTag, ChaCha20Poly1305},
    kdf::HkdfSha384,
    kem::X25519HkdfSha256,
    Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable,
};

use rand::{rngs::StdRng, SeedableRng};

mod data_packets_manager;
mod ciphersuite_server;


// TODO: encryption context (struct?) rfc 5.1

const INFO_STR: &[u8] = b"example session";

// Algorithms
type Kem = X25519HkdfSha256;
type Aead = ChaCha20Poly1305;
type Kdf = HkdfSha384;


// Initializes the server with a fresh keypair
fn server_init() -> (<Kem as KemTrait>::PrivateKey, <Kem as KemTrait>::PublicKey) {
    let mut csprng = StdRng::from_entropy();
    Kem::gen_keypair(&mut csprng)
}


fn server_decrypt_msg(
    server_sk_bytes: &[u8],
    encapped_key_bytes: &[u8],
    ciphertext: &[u8],
    associated_data: &[u8],
    tag_bytes: &[u8],
) -> Vec<u8> {
    // We have to derialize the secret key, AEAD tag, and encapsulated pubkey. 
    // These fail if the bytestrings are the wrong length.
    let server_sk = <Kem as KemTrait>::PrivateKey::from_bytes(
        server_sk_bytes
    ).expect("could not deserialize server privkey!");
    let tag = AeadTag::<Aead>::from_bytes(
        tag_bytes
    ).expect("could not deserialize AEAD tag!");
    let encapped_key = <Kem as KemTrait>::EncappedKey::from_bytes(
        encapped_key_bytes
    ).expect("could not deserialize the encapsulated pubkey!");

    // Decapsulate and derive the shared secret. This creates a shared AEAD context.
    // Inside setup_receiver(), decap() is made
    let mut receiver_ctx =
        hpke::setup_receiver::<Aead, Kdf, Kem>(
            &OpModeR::Base,
            &server_sk,
            &encapped_key,
            INFO_STR
        ).expect("failed to set up receiver!");

    // On success, open_in_place_detached() will decrypt the ciphertext in place
    let mut ciphertext_copy = ciphertext.to_vec();
    receiver_ctx
        .open_in_place_detached(
            &mut ciphertext_copy,
            associated_data,
            &tag
        ).expect("invalid ciphertext!");

    // Rename for clarity. Cargo clippy thinks it's unnecessary, but I disagree
    #[allow(clippy::let_and_return)]
    let plaintext = ciphertext_copy;
    plaintext
}


// Controlla che siano stati riempiti i vettori che servono per decriptare il messaggio
fn ready(ek: &Vec<u8>, ct: &Vec<u8>, ad: &Vec<u8>, tb: &Vec<u8>) -> bool {
    if !ek.is_empty()
    && !ct.is_empty()
    && !ad.is_empty()
    && !tb.is_empty() {
        return true;
    }
    return false;
}


// Gestisce l'arrivo del pacchetto memorizzandolo nel corretto vettore
fn handle_data(mut stream: &TcpStream, vec: &mut Vec<u8>, buf: &[u8], mex: &[u8]) -> Result<(), Error> {
    let id = buf[0];
    let dtype = data_packets_manager::int_to_datatype_display(id);
    println!("Arrivato {}", dtype);
    display_buf(&buf);
    let bytes_written = stream.write(mex)?;
    if bytes_written == 0 {return Ok(());}
    fill_vec_from_buf(vec, &buf);
    Ok(display_vec(&vec))
}


fn handle_data_cps(mut stream: &TcpStream, vec: &mut Vec<String>, buf: &[u8], mex: &[u8]) -> Result<(), Error> {
    let id = buf[0];
    let dtype = data_packets_manager::int_to_datatype_display(id);
    println!("Arrivato {}", dtype);
    display_buf(&buf);
    let bytes_written = stream.write(mex)?;
    if bytes_written == 0 {return Ok(());}
    fill_vec_from_buf_cps(vec, &buf);
    Ok(display_vec_cps(&vec))
}


// Rimpie il vettore con i dati dentro al buffer
fn fill_vec_from_buf(vec: &mut Vec<u8>, buf: &[u8]) {
    let mut ii:usize = 2;
    let pack_len = buf[1];

    loop {
        while ii <= ((pack_len + 1)).into() {
            vec.push(buf[ii]);
            ii += 1;
        }
        break;
    }
}


fn fill_vec_from_buf_cps(vec: &mut Vec<String>, buf: &[u8]) -> Result<(), Error> {
    let mut ii:usize = 2;
    let pack_len = buf[1];
    let mut tmp_vec = vec![];

    Ok(
        loop {
            while ii <= ((pack_len + 1)).into() {
                tmp_vec.push(buf[ii]);
                ii += 1;
            }
            let str = String::from_utf8(tmp_vec).expect("failed to convert");
            vec.push(str);
            break;
        }
    )
}


// Printa un vettore
fn display_vec(vec: &Vec<u8>) {
    print!("vettore: ");
    for i in vec { print!("{} ", i); }
    print!("\n\n");
}


fn display_vec_cps(vec: &Vec<String>) {
    print!("vettore: ");
    for i in vec { print!("{} ", i); }
    print!("\n\n");
}


// Printa un buffer
fn display_buf(buf: &[u8]) {
    print!("data: ");
    for i in buf { print!("{} ", i); }
    print!("\n");
}


// Controlla che ci sia almeno un algoritmo in comune tra C e S
// Se esiste, ritorna l'ID DELL'ULTIMO controllato, 
//e un flag che segnala che esiste almeno un algoritmo in comune 
fn match_available_cps(av_client: &Vec<String>, av_server: &Vec<String>) -> (String, bool) {
    let mut id =  String::from("None");
    let mut pass = false;
    for i in av_client {
        for j in av_server {
            if i == j {
                // esiste un algoritmo compatibile
                pass = true;  
                id = j.to_string(); 
            }
        }
    }
    (id, pass)
}


fn send_packet(mut stream: &TcpStream, pack: &[u8], received_mex: &mut [u8], what: String) {
    stream.write(pack).unwrap();
    println!("\n{} inviata", what);

    match stream.read(received_mex) {

        Ok(_) => {
            if received_mex == [0] { println!("Il client ha ricevuto {}\n", what) }
        },
        
        Err(e) => {
            println!("Fallimento nel ricevere dati: {}", e);
            return;
        }
    }
}


// Primary server responds to the primary client with one of the
// available ciphersuites and shares its public key.
fn handle_client(mut stream: &TcpStream, pubkey: &[u8], privkey: &[u8], mex: &[u8]) -> Result<(), Error> {

    let mut received = [1 as u8];

    // vettori dove vengono salvati gli algoritmi del C
    let mut client_kem_cps = vec![];
    let mut client_kdf_cps = vec![];
    let mut client_aead_cps = vec![];

    // vettori che contengono gli algoritmi disponibili del S
    let server_av_kems = ciphersuite_server::KEMtypeR::to_vect();
    let server_av_kdfs = ciphersuite_server::KDFtypeR::to_vect();
    let server_av_aeads = ciphersuite_server::AEADtypeR::to_vect();

    // bool che segnalano se esiste almeno un algoritmo disponibile in comune ta C e S
    let mut kem_pass = false;
    let mut kdf_pass = false;
    let mut aead_pass = false;

    println!("Incoming connection from: {}\n", stream.peer_addr()?);

    // IL BUFFER DATA PUÒ ESSERE MOLTO PIÙ GRANDE
    let mut data = [0 as u8; 100]; 

    loop {

        let mut finish_cps = false;   // segnala quando il client ha inviato tutti
                                            // gli algoritmi che ha a disposizione     

        let bytes_read = stream.read(&mut data)?;
        if bytes_read == 0 {return Ok(());}


        // ##### ARRIVO DELLE CIPHERSUITES DAL CLIENT #####

        // => KEM
        if data[0] == 5 && !finish_cps {
            handle_data_cps(stream, &mut client_kem_cps, &data, mex)?;
        }
        // => KDF
        if data[0] == 6 && !finish_cps {
            handle_data_cps(stream, &mut client_kdf_cps, &data, mex)?;
        }
        // => AEAD
        if data[0] == 7 && !finish_cps {
            handle_data_cps(stream, &mut client_aead_cps, &data, mex)?;
        }
        // Invio di pecchetti terminato
        if data[0] == 8 && !finish_cps {
            finish_cps = true;
            println!("Arrivata tutta la cps del client\n");
        }
        // Trovata una ciphersuite comune -> esci
        if data[0] == 9 {
            println!("Il client ha ricevuto tutto!");
            break;
        }


        // ##### CONTROLLO SE ESEITE UNA CIPHERSUITE COMUNE COL CLIENT #####

        if finish_cps {

            // ID degli algoritmi scelti
            let kem_id:String;
            let kdf_id:String;
            let aead_id:String; 
        
            println!("Controllo quali algoritmi sono disponibili...\n");

            // => KEM
            (kem_id, kem_pass) = match_available_cps(
                &client_kem_cps,
                &server_av_kems
            );   
            // => KDF
            (kdf_id, kdf_pass) = match_available_cps(
                &client_kdf_cps,
                &server_av_kdfs
            );      
            // => AEAD
            (aead_id, aead_pass) = match_available_cps(
                &client_aead_cps,
                &server_av_aeads
            );
            
            println!("KEM ID: {}", kem_id);
            println!("KDF ID: {}", kdf_id);
            println!("AEAD ID: {}", aead_id);

            
            // Se esiste una ciphersuite completa tra C e S, segnala
            // al client quale algoritmo usare e invia la chiave pubblica
            if kem_pass && kdf_pass && aead_pass {

                // ##### INVIO CIPHERSUITE AL CLIENT #####

                // => KEM
                let kem_id_pack = data_packets_manager::create_packet(
                    data_packets_manager::DataType::Enc_ctx_KEM,
                    kem_id.into_bytes()
                );
                let kem_id_data_pack = kem_id_pack.group();
                let kem_id_data_pack_bytes = kem_id_data_pack.as_slice();
                send_packet(stream, kem_id_data_pack_bytes, &mut received, String::from("Choosen KEM cps"));

                // => KEM
                let kdf_id_pack = data_packets_manager::create_packet(
                    data_packets_manager::DataType::Enc_ctx_KDF,
                    kdf_id.into_bytes()
                );
                let kdf_id_data_pack = kdf_id_pack.group();
                let kdf_id_data_pack_bytes = kdf_id_data_pack.as_slice();
                send_packet(stream, kdf_id_data_pack_bytes, &mut received, String::from("Choosen KDF cps"));

                // => KEM
                let aead_id_pack = data_packets_manager::create_packet(
                    data_packets_manager::DataType::Enc_ctx_AEAD,
                    aead_id.into_bytes()
                );
                let aead_id_data_pack = aead_id_pack.group();
                let aead_id_data_pack_bytes = aead_id_data_pack.as_slice();
                send_packet(stream, aead_id_data_pack_bytes, &mut received, String::from("Choosen AEAD cps"));

                // => Puclic Key
                let pub_key_pack = data_packets_manager::create_packet(
                    data_packets_manager::DataType::PublicKey,
                    pubkey.to_vec()
                );
                let pub_key_data_pack = pub_key_pack.group();
                let pub_key_data_pack_bytes = pub_key_data_pack.as_slice();
                send_packet(stream, pub_key_data_pack_bytes, &mut received, String::from("Public Key"));
            }
        }
    }
    Ok(())
}


fn client_exchange_mex(mut stream: &TcpStream, pubkey: &[u8], privkey: &[u8], mex: &[u8]) -> Result<(), Error> {
    let mut ek:Vec<u8> = vec![]; 
    let mut ct:Vec<u8> = vec![]; 
    let mut ad:Vec<u8> = vec![];  
    let mut tb:Vec<u8> = vec![]; 

    // IL BUFFER DATA PUÒ ESSERE MOLTO PIÙ GRANDE
    let mut data = [0 as u8; 100]; 

    loop {

        let bytes_read = stream.read(&mut data)?;

        if bytes_read == 0 {return Ok(());}

        // Richiesta della chiave pubblica => 0
        if data[0] == 0 {
            stream.write(pubkey)?;
            println!("Chiave pubblica server inviata\n");
        }

        // Memorizzazione dei pacchetti arrivati
        // Arrivo della Encapped Key => 1 
        else if data[0] == 1 {
            handle_data(stream, &mut ek, &data, mex)?;
        }
        // Arrivo del CipherText => 2 
        else if data[0] == 2 {
            handle_data(stream, &mut ct, &data, mex)?;
        }
        // Arrivo di AssociatedData => 3
        else if data[0] == 3 {
            handle_data(stream, &mut ad, &data, mex)?;
        }
        // Arrivo di Tag => 4 
        else if data[0] == 4 {
            handle_data(stream, &mut tb, &data, mex)?;
        }


        if ready(&ek, &mut ct, &mut ad, &mut tb) {
            // Decripta il messaggio
            let decrypted_msg = server_decrypt_msg(
                privkey,
                ek.as_slice(),
                ct.as_slice(),
                ad.as_slice(),
                tb.as_slice()
            );

            /* Il messaggio ricevuto viene mandato indietro 
            al client per verificare che sia corretto */
            stream.write(&decrypted_msg)?;
            println!("Ho riscritto al client");
        }
    }
}


fn main() {

    let ok_mex = [0 as u8];

    let remote: SocketAddr = "0.0.0.0:8888".parse().unwrap();

    //Generazione di chiave pubblica e privata del server
    let (server_prikey, server_pubkey) = server_init();

    let server_pubkey_bytes = server_pubkey.to_bytes();
    let server_prikey_bytes = server_prikey.to_bytes();
    
    //let s_puk_size = server_pubkey_bytes.len();
    //println!("dim chiave pub {}", s_puk_size);
    
    let listener = TcpListener::bind(remote).expect("Could not bind");

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                // TODO: handle client servirà per la negoziazione; lo scambio di messaggi è successivo
                handle_client(
                    &stream,
                    &server_pubkey_bytes,
                    &server_prikey_bytes, 
                    &ok_mex
                ).unwrap();

                client_exchange_mex(
                    &stream,
                    &server_pubkey_bytes,
                    &server_prikey_bytes, 
                    &ok_mex
                ).unwrap();
            }
            Err(e) => { 
                eprintln!("failed: {}", e) 
            }
        }
    }

    // close the socket server
    drop(listener);

}