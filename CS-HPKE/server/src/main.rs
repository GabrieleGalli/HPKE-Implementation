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


fn ready(ek: &[u8], ct: &mut [u8], ad: &mut [u8], tb: &mut [u8]) -> bool {
    if ek != [0 as u8; ek.len()] 
    && ct != [0 as u8; ct.len()]
    && ad != [0 as u8; ad.len()]
    && tb != [0 as u8; tb.len()] {
        return true;
    }
    return false;
}


// Initializes the server with a fresh keypair
fn server_init() -> (<Kem as KemTrait>::PrivateKey, <Kem as KemTrait>::PublicKey) {
    let mut csprng = StdRng::from_entropy();
    Kem::gen_keypair(&mut csprng)
}


fn handle_client(
    mut stream: &TcpStream, 
    pubkey: &[u8], 
    privkey: &[u8], 
    mex: &[u8]
) -> Result<(), Error> {
    println!("Incoming connection from: {}", stream.peer_addr()?);

    let ek: &[u8];
    let ct: &[u8];
    let ad: &[u8];
    let tb: &[u8];

    let mut data = [0 as u8; 100]; 

    loop {
        let bytes_read = stream.read(&mut data)?;
        if bytes_read == 0 {return Ok(());}

        // Richiesta della chiave pubblica => 0
        if data[0] == 0 {
            stream.write(pubkey)?;
            println!("Chiave pubblica server inviata");
        }
        // Arrivo della Encapped Key => 1 
        else if data[0] == 1 {
            println!("Arrivata EncappedKey");
            stream.write(mex)?;
            let len = data.len();
            ek = &data[1..len];
        }
        // Arrivo del CipherText => 2 
        else if data[0] == 2 {
            println!("Arrivato Ciphertext");
            stream.write(mex)?;
            let len = data.len();
            ct = &data[1..len];
        }
        // Arrivo di AssociatedData => 3
        else if data[0] == 3 {
            println!("Arrivato AssociatedData");
            stream.write(mex)?;
            let len = data.len();
            ad = &data[1..len];
        }
        // Arrivo di Tag => 4 
        else if data[0] == 4 {
            println!("Arrivato Tag");
            stream.write(mex)?;
            let len = data.len();
            tb = &data[1..len];
        }

        if ready(&ek, &mut ct, &mut ad, &mut tb) {
            let decrypted_msg = server_decrypt_msg(
                privkey,
                ek,
                ct,
                ad,
                tb
            );
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