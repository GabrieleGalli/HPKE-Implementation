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

// Cripta il messaggio
fn client_encrypt_msg(
    msg: &[u8], 
    associated_data: &[u8], 
    server_pk: &<Kem as KemTrait>::PublicKey,
) -> (<Kem as KemTrait>::EncappedKey, Vec<u8>, AeadTag<Aead>) {
    let mut csprng = StdRng::from_entropy();

    let (encapped_key, mut sender_ctx) =
        hpke::setup_sender::<Aead, Kdf, Kem, _>(
            &OpModeS::Base,
            server_pk,
            INFO_STR, 
            &mut csprng
        ).expect("invalid server pubkey!");

    let mut msg_copy = msg.to_vec();
    let tag = 
        sender_ctx.seal_in_place_detached(
            &mut msg_copy,
            associated_data
        ).expect("encryption failed!");

    let ciphertext = msg_copy;

    (encapped_key, ciphertext, tag)
}

fn send_packet(stream:&mut TcpStream, pack: &[u8], received_mex: &mut [u8], what: String) {
    stream.write(pack).unwrap();
    println!("{} inviata", what);

    match stream.read(received_mex) {
        Ok(_) => {
            if received_mex == [0] {
                println!("Il server ha ricevuto {}", what)
            }
        },
        Err(e) => {
            println!("Fallimento nel ricevere dati: {}", e);
            return;
        }
    }
}

// Printa il pacchetto completo
fn display_pack(pack: &[u8]) {
    let id = pack[0];
    let dtype = data_packets_manager::int_data_type_display(id);
    print!("{}: ", dtype);
    let mut count:i8 = 0;
    for i in pack {
        count+=1;
        print!("{} ",i);
    }
    println!("\nlen: {}\n", count);
}


fn main() {
    let remote: SocketAddr = "127.0.0.1:8888".parse().unwrap();

    let mut server_pubkey_bytes = [0 as u8; 32];

    match TcpStream::connect(remote) {
        Ok(mut stream) => {
            println!("\nConnessione al server avviata alla porta {}", remote);

            let key_req = [0 as u8];
            stream.write(&key_req).unwrap();
            
            println!("\nRichiesta chiave pubblica inviata");

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

    // Recupera la serve public key
    let server_pubkey = 
        <Kem as KemTrait>::PublicKey::from_bytes(
            &mut server_pubkey_bytes
        ).expect("could not deserialize the encapsulated pubkey!");
    
    
    loop {
        // Testo che deve essere mandato criptato
        println!("\nInserisci testo");
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
        let ek = encapped_key.to_bytes().to_vec();
        let ek_data_pack = data_packets_manager::create_packet(
            DataType::EncappedKey,
            ek
        );
        let ek_pack = ek_data_pack.group();
        let ek_data_packet_byte = ek_pack.as_slice();

        // => ChiperText
        let ct_clone = ciphertext.clone();
        let ct_data_pack = data_packets_manager::create_packet(
            DataType::Ciphertext,
            ct_clone
        );
        let ct_pack = ct_data_pack.group();
        let ct_data_packet_byte = ct_pack.as_slice();

        // => AssociatedData
        let ad = associated_data.to_vec();
        let ad_data_pack = data_packets_manager::create_packet(
            DataType::AssociatedData,
            ad
        );
        let ad_pack = ad_data_pack.group();
        let ad_data_packet_byte = ad_pack.as_slice();

        // => TagBytes
        let tb = tag.to_bytes().to_vec();
        let tb_data_pack = data_packets_manager::create_packet(
            DataType::TagBytes,
            tb
        );
        let tb_pack = tb_data_pack.group();
        let tb_data_packet_byte = tb_pack.as_slice();

        // Invio dei pacchetti
        match TcpStream::connect(remote) {
            Ok(mut stream) => {
                let mut received = [0 as u8; 1];

                println!("\nInvio pacchetti al server...\n");

                // INVIO ENCAPPEDKEY
                send_packet(
                    &mut stream,
                    ek_data_packet_byte,
                    &mut received, 
                    String::from("EncappedKey")
                );
                display_pack(ek_data_packet_byte);

                // INVIO DI CIPHERTEXT
                send_packet(
                    &mut stream,
                    ct_data_packet_byte,
                    &mut received, 
                    String::from("Ciphertext")
                );
                display_pack(ct_data_packet_byte);

                // INVIO DI ASSOCIATEDDATA               
                send_packet(
                    &mut stream,
                    ad_data_packet_byte,
                    &mut received, 
                    String::from("AssociatedData")
                );
                // test asssociated data
                display_pack(ad_data_packet_byte);

                // INVIO DI TAG               
                send_packet(
                    &mut stream,
                    tb_data_packet_byte,
                    &mut received, 
                    String::from("Tag")
                );
                display_pack(tb_data_packet_byte);

                // RICEZIONE DEL CONTENUTO MANDATO
                let mut buf = [0 as u8; 100];
                let bytes_read = stream.read(&mut buf);
                let mut msg = buf.to_vec();
                let msg = str::from_utf8(&msg).unwrap();
                println!("Il server ha inviato: {}", msg);

            },
            Err(e) => {
                println!("Fallimento nel connettersi: {}", e);
                return;
            },
        }     
    }
}