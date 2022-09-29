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

fn client_encrypt_msg(msg: &[u8], associated_data: &[u8], server_pk: &<Kem as KemTrait>::PublicKey,) -> (<Kem as KemTrait>::EncappedKey, Vec<u8>, AeadTag<Aead>) {
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

fn main() {
    let remote: SocketAddr = "127.0.0.1:8888".parse().unwrap();
    let mut stream = TcpStream::connect_timeout(&remote, Duration::from_secs(2)).expect("Could not connect to server");

    //stream.set_read_timeout(Some(Duration::from_secs(3))).expect("Could not set a read timeout");
    println!("Connessione al server avviata");

    let associated_data = b"a tutti";

    // Dal server a cui si è connesso arriva la chiave pubblica
    let mut server_pubkey_bytes: Vec<u8> = Vec::new();
    let mut reader = BufReader::new(&stream);
    reader.read_until(b'\n', &mut server_pubkey_bytes).expect("Could not read into buffer");

    println!("Chiave pubblica server ricevuta");

    let server_pubkey = <Kem as KemTrait>::PublicKey::from_bytes(&server_pubkey_bytes)
        .expect("could not deserialize the encapsulated pubkey!");


    loop {
        println!("Inserisci testo");
        // testo che deve essere mandato criptato
        let mut input = String::new();

        io::stdin().read_line(&mut input).expect("Failed to read");

        // Let the client send a message to the server using the server's pubkey
        let (encapped_key, ciphertext, tag) =   
            client_encrypt_msg(
                input.as_bytes(), 
                associated_data, 
                &server_pubkey);

        // Operazioni per mandare pacchetti riconoscibili: EncappedKey, Ciphertext(Vec<u8>), AssociatedData, TagBytes
        // => EncappedKey
        let ek_data_type = DataType::EncappedKey(&encapped_key);
        let ek_id = data_type_int(ek_data_type);        
        let ek_data_packet = DataPacket {
            header: ek_id,
            payload: encapped_key.to_bytes().to_vec()
        };
        let ek_data_packet_byte = ek_data_packet.to_bytes();

        stream.write(&ek_data_packet_byte).expect("Failed to write to server");
        println!("mandata encapKey");

        // => ChiperText
        let ct_data_type = DataType::Ciphertext(&ciphertext);
        let ct_id = data_type_int(ct_data_type);
        let ct_data_packet = DataPacket {
            header: ct_id,
            payload: ciphertext
        };
        let ct_data_packet_byte = ct_data_packet.to_bytes();

        stream.write(&ct_data_packet_byte).expect("Failed to write to server");
        println!("mandata ciphertext");
    
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