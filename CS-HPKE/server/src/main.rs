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

const INFO_STR: &[u8] = b"example session";

// Algorithms
type Kem = X25519HkdfSha256;
type Aead = ChaCha20Poly1305;
type Kdf = HkdfSha384;


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
        .open_in_place_detached(&mut ciphertext_copy, associated_data, &tag)
        .expect("invalid ciphertext!");

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

// Initializes the server with a fresh keypair
fn server_init() -> (<Kem as KemTrait>::PrivateKey, <Kem as KemTrait>::PublicKey) {
    let mut csprng = StdRng::from_entropy();
    Kem::gen_keypair(&mut csprng)
}

// Gestisce l'arrivo del ppacchetto memorizzandolo nel corretto vettore
fn handle_data(mut stream: &TcpStream, vec: &mut Vec<u8>, buf: &[u8], mex: &[u8]) -> Result<(), Error> {
    let id = buf[0];
    let dtype = data_packets_manager::int_data_type_display(id);
    println!("Arrivato {}", dtype);
    display_data(&buf);
    let bytes_written = stream.write(mex)?;
    if bytes_written == 0 {return Ok(());}
    fill_vec(vec, &buf);
    Ok(display_vec(&vec))
}

// Rimpie il vettore con i dati dentro al buffer
fn fill_vec(vec: &mut Vec<u8>, buf: &[u8]) {
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

// Printa un vettore
fn display_vec(vec: &Vec<u8>) {
    print!("vettore: ");
    for i in vec { print!("{} ", i); }
    print!("\n\n");
}

// Printa un buffer
fn display_data(buf: &[u8]) {
    print!("data: ");
    for i in buf { print!("{} ", i); }
    print!("\n");
}

// Gestisce la comunicazione con un client
fn handle_client(mut stream: &TcpStream, pubkey: &[u8], privkey: &[u8], mex: &[u8]) -> Result<(), Error> {
    println!("Incoming connection from: {}\n", stream.peer_addr()?);

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

            /* Il messaggio ricevuto viene mandato indietro al client 
            per verificare che sia corretto */
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
                handle_client(
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