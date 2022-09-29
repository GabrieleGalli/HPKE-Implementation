use std::net::{TcpListener, TcpStream, Shutdown};
use std::net::SocketAddr;
use std::io::{Read, Write, Error, BufReader};

use hpke::{
    aead::{AeadTag, ChaCha20Poly1305},
    kdf::HkdfSha384,
    kem::X25519HkdfSha256,
    Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable,
};

use rand::{rngs::StdRng, SeedableRng};

// These are the only algorithms we're gonna use for this example
type Kem = X25519HkdfSha256;
type Aead = ChaCha20Poly1305;
type Kdf = HkdfSha384;

// Initializes the server with a fresh keypair
fn server_init() -> (<Kem as KemTrait>::PrivateKey, <Kem as KemTrait>::PublicKey) {
    let mut csprng = StdRng::from_entropy();
    Kem::gen_keypair(&mut csprng)
}

fn handle_client(mut stream: &TcpStream, server_pk: &[u8]) -> Result<(), Error> {
    println!("Incoming connection from: {}", stream.peer_addr()?);
    stream.write(server_pk)?;
    println!("chiave pubblica server inviata");
    return Ok(());
}

fn receive_packs(mut stream: &TcpStream) -> Result<(), Error> {
    let mut buf = [0; 512];
    while match stream.read(&mut buf) { 
        Ok(size) => {
            if buf[buf.len()-1] == 1 {
                stream.write(b"ricevuta EncapKey");
            } else if buf[buf.len()-1] == 2 {
                stream.write(b"ricevuta ciphertext");
            }
            // echo everything!
            //stream.write(&data[0..size]).unwrap();
            true
        },
        Err(_) => {
            println!("An error occurred, terminating connection with {}", stream.peer_addr().unwrap());
            stream.shutdown(Shutdown::Both).unwrap();
            false
        }
    } {}
    return Ok(());
}

fn main() {
    let remote: SocketAddr = "0.0.0.0:8888".parse().unwrap();

    let (server_privkey, server_pubkey) = server_init();
    let server_pubkey_bytes = server_pubkey.to_bytes();
    
    let listener = TcpListener::bind(remote).expect("Could not bind");

    for stream in listener.incoming() {
        match stream {
            Err(e) => { eprintln!("failed: {}", e) }
            Ok(stream) => {
                handle_client(&stream, &server_pubkey_bytes).unwrap();
                receive_packs(&stream);
            }
        }
    }
}