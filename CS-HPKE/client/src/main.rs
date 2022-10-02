use std::net:: { TcpStream, SocketAddr };
use std::str;
use std::io::{self, BufRead, BufReader, Write, Read};
use std::time::Duration;

use hpke::{
    aead::{AeadTag, ChaCha20Poly1305},
    kdf::HkdfSha384,
    kem::X25519HkdfSha256,
    Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable,
};

use rand::{rngs::StdRng, SeedableRng};

use crate::data_packets_manager::{data_type_int, DataType, DataPacket};

mod data_packets_manager;

const INFO_STR: &[u8] = b"example session";

// These are the only algorithms we're gonna use for this example
type Kem = X25519HkdfSha256;
type Aead = ChaCha20Poly1305;
type Kdf = HkdfSha384;

fn client_encrypt_msg(
    msg: &[u8], 
    associated_data: &[u8], 
    server_pk: &<Kem as KemTrait>::PublicKey,
) -> (<Kem as KemTrait>::EncappedKey, Vec<u8>, AeadTag<Aead>) {
    let mut csprng = StdRng::from_entropy();

    let (encapped_key, mut sender_ctx) =
        hpke::setup_sender::<Aead, Kdf, Kem, _>(&OpModeS::Base, server_pk, INFO_STR, &mut csprng)
            .expect("invalid server pubkey!");

    let mut msg_copy = msg.to_vec();
    let tag = sender_ctx
        .seal_in_place_detached(&mut msg_copy, associated_data)
        .expect("encryption failed!");

    let ciphertext = msg_copy;

    (encapped_key, ciphertext, tag)
}

fn send_packet(
    stream:&mut TcpStream, 
    pack: &[u8], 
    received_mex: &mut [u8], 
    what: String
) {
    stream.write(pack).unwrap();
    println!("{} inviata", what);

    match stream.read(received_mex) {
        Ok(_) => {
            if received_mex == [0] {
                println!("il server ha ricevuto {}", what)
            }
        },
        Err(e) => {
            println!("Fallimento nel ricevere dati: {}", e);
            return;
        }
    }
}

fn main() {
    let remote: SocketAddr = "127.0.0.1:8888".parse().unwrap();

    let mut server_pubkey_bytes = [0 as u8; 32];
    // let mut res_mex = [0 as u8];

    match TcpStream::connect(remote) {
        Ok(mut stream) => {
            println!("Connessione al server avviata alla porta {}", remote);

            let key_req = [0 as u8];
            stream.write(&key_req).unwrap();
            
            println!("Richiesta chiave pubblica inviata");

            match stream.read(&mut server_pubkey_bytes) {
                Ok(_) => {
                    println!("Chiave pubblica ricevuta");
                },
                Err(e) => {
                    println!("Fallimento nel ricevere dati: {}", e);
                }
            }
        },
        Err(e) => {
            println!("Fallimento nel connettersi: {}", e);
            return;
        },
    }

    let server_pubkey = 
        <Kem as KemTrait>::PublicKey::from_bytes(&mut server_pubkey_bytes)
            .expect("could not deserialize the encapsulated pubkey!");
    
    
    loop {
        // Testo che deve essere mandato criptato
        println!("Inserisci testo");
        let mut input = String::new();
        io::stdin().read_line(&mut input).expect("Failed to read");

        let associated_data = b"associated data";

        // Let the client send a message to the server using the server's pubkey
        let (encapped_key, ciphertext, tag) =   
            client_encrypt_msg(
                input.as_bytes(), 
                associated_data, 
                &server_pubkey
            );


        // Operazioni per mandare pacchetti riconoscibili: 
        // EncappedKey, Ciphertext(Vec<u8>), AssociatedData, TagBytes

        // => EncappedKey
        let ek_clone = encapped_key.clone();
        let ek_data_type = DataType::EncappedKey(ek_clone);
        let ek_id = data_type_int(ek_data_type);        
        let ek_data_packet = DataPacket {
            header: ek_id,
            payload: encapped_key.to_bytes().as_slice().to_vec()
        };
        let tmp = ek_data_packet.group();
        let ek_data_packet_byte= tmp.as_slice();

        // => ChiperText
        let ct_clone = ciphertext.clone();
        let ct_data_type = DataType::Ciphertext(ciphertext);
        let ct_id = data_type_int(ct_data_type);
        let ct_data_packet = DataPacket {
            header: ct_id,
            payload: ct_clone
        };
        let tmp = ct_data_packet.group();
        let ct_data_packet_byte = tmp.as_slice();
        
        // => AssociatedData
        // => TagBytes
        

        // Invio dei pacchetti
        match TcpStream::connect(remote) {
            Ok(mut stream) => {
                let mut received = [0 as u8; 1];

                println!("Invio pacchetti ek e ct al server");

                send_packet(
                    &mut stream,
                    ek_data_packet_byte,
                    &mut received, 
                    String::from("ek")
                );

                send_packet(
                    &mut stream,
                    ct_data_packet_byte,
                    &mut received, 
                    String::from("ek")
                );
            },
            Err(e) => {
                println!("Fallimento nel connettersi: {}", e);
                return;
            },
        }
    

        

        /* 
        stream.write(&ek_data_packet_byte).expect("Failed to write to server");
        println!("mandata encapKey");

        stream.write(&ct_data_packet_byte).expect("Failed to write to server");
        println!("mandata ciphertext");
        */

        /*

        let encapped_key_bytes = encapped_key.to_bytes();
        let tag_bytes = tag.to_bytes();

        stream.write(input.as_bytes()).expect("Failed to write to server");

        let mut reader = BufReader::new(&stream);

        reader.read_until(b'\n', &mut buffer).expect("Could not read into buffer");
        print!("{}", str::from_utf8(&buffer).expect("Could not write buffer as string"));

        */
    }
}