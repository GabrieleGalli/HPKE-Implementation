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

// Algorithms
type Kem = X25519HkdfSha256;
type Aead = ChaCha20Poly1305;
type Kdf = HkdfSha384;

// Initializes the server with a fresh keypair
fn server_init() -> (<Kem as KemTrait>::PrivateKey, <Kem as KemTrait>::PublicKey) {
    let mut csprng = StdRng::from_entropy();
    Kem::gen_keypair(&mut csprng)
}

fn handle_client(mut stream: &TcpStream, server_pk: &[u8], mex: &[u8]) -> Result<(), Error> {

    println!("Incoming connection from: {}", stream.peer_addr()?);

    let mut data = [0 as u8; 100]; 

    loop {
        let bytes_read = stream.read(&mut data)?;
        if bytes_read == 0 {return Ok(());}
        // Richiesta della chiave pubblica => 0:48
        if data[0] == 0 {
            stream.write(server_pk)?;
            println!("Chiave pubblica server inviata");
        }
        // Arrivo della Encapped Key => 1 
        else if data[0] == 1 {
            println!("Arrivata ek");
            stream.write(mex)?;
        }
        // Arrivo del CipherText => 2 
        else if data[0] == 2 {
            println!("Arrivato ct");
            stream.write(mex)?;
        }
        // Arrivo di AssociatedData => 3
        else if data[0] == 2 {
            println!("Arrivato ad");
            stream.write(mex)?;
        }
        // Arrivo di TagBytes => 4 
        else if data[0] == 2 {
            println!("Arrivato tb");
            stream.write(mex)?;
        }
    }
    /*
    while match stream.read(&mut data) {
        // Lettura dei pacchetti in arrivo
        Ok(_) => {
            // Richiesta della chiave pubblica => 0:48
            if data[0] == 48 { 
                stream.write(server_pk)?;
                println!("Chiave pubblica server inviata");
            }
            // Arrivo della Encapped Key => 0:49
            if data[0] == 49 {
                println!("Arrivata ek");
                stream.write(mex)?;
            }
            true
        },
        Err(e) => {
            println!("An error occurred: {}\nTerminating connection with {}", e,stream.peer_addr().unwrap());
            stream.shutdown(Shutdown::Both).unwrap();
            false
        }
    } {}
    */
    return Ok(());
}


fn main() {
    let ok_mex = [0 as u8];

    let remote: SocketAddr = "0.0.0.0:8888".parse().unwrap();

    //Generazione di chiave pubblica e privata del server
    let (server_privkey, server_pubkey) = server_init();

    let server_pubkey_bytes = server_pubkey.to_bytes();
    let s_puk_size = server_pubkey.to_bytes().len();
    println!("dim chiave pub {}", s_puk_size);
    
    let listener = TcpListener::bind(remote).expect("Could not bind");

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                handle_client(&stream, &server_pubkey_bytes, &ok_mex).unwrap();
            }
            Err(e) => { 
                eprintln!("failed: {}", e) 
            }
        }
    }
    // close the socket server
    drop(listener);
}