use std::net:: { TcpStream, SocketAddr };
use std::{str, clone};
use std::io::{self, BufRead, BufReader, Write, Read, Error};
use std::time::Duration;

use hpke::{
    aead::{AeadTag, AesGcm128, AesGcm256, ChaCha20Poly1305, ExportOnlyAead},
    kdf::{HkdfSha256, HkdfSha384, HkdfSha512},
    kem::{X25519HkdfSha256, DhP256HkdfSha256},
    Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable,
};

use rand::{rngs::StdRng, SeedableRng};

mod data_packets_manager;
mod ciphersuite_client;

const INFO_STR: &[u8] = b"example session";


// These are the only algorithms we're gonna use for this example
type Kem = X25519HkdfSha256;
type Aead = ChaCha20Poly1305;
type Kdf = HkdfSha384;


fn client_init() -> (<Kem as KemTrait>::PrivateKey, <Kem as KemTrait>::PublicKey) {
    let mut csprng = StdRng::from_entropy();
    Kem::gen_keypair(&mut csprng)
}


// Cripta il messaggio
fn client_encrypt_msg(msg: &[u8], associated_data: &[u8], server_pk: &<Kem as KemTrait>::PublicKey) 
    -> (<Kem as KemTrait>::EncappedKey, Vec<u8>, AeadTag<Aead>) {
    let mut csprng = StdRng::from_entropy();

    // Inside setup_sender(), encap() is made
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
            if received_mex == [0] { println!("Il server ha ricevuto {}", what) }
        },
        
        Err(e) => {
            println!("Fallimento nel ricevere dati: {}", e);
            return;
        }
    }
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


fn display_buf(buf: &[u8]) {
    print!("data: ");
    for i in buf { print!("{} ", i); }
    print!("\n");
}


fn display_vec(vec: &Vec<u8>) {
    print!("vettore: ");
    for i in vec { print!("{} ", i); }
    print!("\n\n");
}


// Printa il pacchetto completo
fn display_pack(pack: &[u8]) {
    let id = pack[0];
    let dtype = data_packets_manager::int_to_datatype_display(id);
    print!("{}: ", dtype);
    let mut count:i8 = 0;
    for i in pack {
        count+=1;
        print!("{} ",i);
    }
    println!("\nlen: {}\n", count);
}


fn handle_server(
    remote: SocketAddr,
    stream: &mut TcpStream, 
    server_pk: &mut Vec<u8>,
    kem: &mut String, 
    kdf: &mut String, 
    aead: &mut String,
    available_kem_cps: &Vec<String>,
    available_kdf_cps: &Vec<String>,
    available_aead_cps: &Vec<String>,
) -> Result<(), Error> {

    let mut received = [1 as u8];
    let finish_cps = [8 as u8];
    let finish_cps2 = [9 as u8];
    let mut data = [0 as u8; 100]; 

    println!("\nConnessione al server avviata alla porta {}", remote);


    // ##### INVIO DELLA CIPHERSUITE DISPONIBILE #####

    println!("\nInvio ciphersuite e richiesta chiave pubblica al server\n");  

    // => KEM
    for i in available_kem_cps {
        let clone = i.clone();
        let kem_cps_pack = data_packets_manager::create_packet(
            data_packets_manager::DataType::Enc_ctx_KEM, 
            clone.into_bytes()
        );
        let kem_cps_data_pack = kem_cps_pack.group();
        let kem_cps_data_pack_bytes = kem_cps_data_pack.as_slice();
        send_packet(stream, kem_cps_data_pack_bytes, &mut received, String::from("KEM cps"));
        display_pack(kem_cps_data_pack_bytes);
    }
    // => KDF
    for j in available_kdf_cps {
        let clone = j.clone();
        let kdf_cps_pack = data_packets_manager::create_packet(
            data_packets_manager::DataType::Enc_ctx_KDF, 
            clone.into_bytes()
        );
        let kdf_cps_data_pack = kdf_cps_pack.group();
        let kdf_cps_data_pack_bytes = kdf_cps_data_pack.as_slice();
        send_packet(stream, kdf_cps_data_pack_bytes, &mut received, String::from("KDF cps"));
        display_pack(kdf_cps_data_pack_bytes);
    }
    // => AEAD
    for k in available_aead_cps {
        let clone = k.clone();
        let aead_cps_pack = data_packets_manager::create_packet(
            data_packets_manager::DataType::Enc_ctx_AEAD, 
            clone.into_bytes()
        );
        let aead_cps_data_pack = aead_cps_pack.group();
        let aead_cps_data_pack_bytes = aead_cps_data_pack.as_slice();
        send_packet(stream, aead_cps_data_pack_bytes, &mut received, String::from("AEAD cps"));
        display_pack(aead_cps_data_pack_bytes);
    }

    stream.write(&finish_cps).unwrap(); // segnala a S che è stato inviato tutto il ciphersuite

    println!("\nCiphersuite e richiesta chiave pubblica inviati");

    let ok_mex = [0 as u8]; // segnala con un write al server la ricezione del pacchetto

    // vect per memorizzare gli algoritmi scelti
    let mut server_pubkey: Vec<u8> = vec![];
    let mut choosen_kem: Vec<u8> = vec![];
    let mut choosen_kdf: Vec<u8> = vec![];
    let mut choosen_aead: Vec<u8> = vec![];

    // flag per segnalare che esiste almeno un algoritmo in comune di quel tipo
    let mut pk_pass = false;
    let mut kem_pass = false;
    let mut kdf_pass = false;
    let mut aead_pass = false;
            

    // ##### RICEZIONE DELLA CIPHERSUITE DEL SERVER #####

    println!("Aspetto la ciphersuite scellta dal server...");

    loop {
               
        let bytes_read = stream.read(&mut data)?;
        if bytes_read == 0 {return Ok(());}

        // => Server's public key
        if data[0] == 0 {
            handle_data(stream, &mut server_pubkey, &data, &ok_mex)?;
            pk_pass = true;
        }
        // => KEM
        if data[0] == 5 {
            handle_data(stream, &mut choosen_kem, &data, &ok_mex)?;
            kem_pass = true;
        }
        // => KDF
        if data[0] == 6 {
            handle_data(stream, &mut choosen_kdf, &data, &ok_mex)?;
            kdf_pass = true;
        }
        // => AEAD
        if data[0] == 7 {
            handle_data(stream, &mut choosen_aead, &data, &ok_mex)?;
            aead_pass = true;
        }
        if pk_pass && kem_pass && kdf_pass && aead_pass {
            println!("Client ha ricevuto la ciphersuite del server");
            break;   
        }

    }
    
    // #### OUTPUT DEI RISULTATI ####
    *server_pk = server_pubkey;
    *kem = String::from_utf8(choosen_kem).unwrap();
    *kdf = String::from_utf8(choosen_kdf).unwrap();
    *aead = String::from_utf8(choosen_aead).unwrap();
    
    //println!("kem {}", kem);
    //println!("kdf {}", kdf);
    //println!("aead {}", aead);

    stream.write(&finish_cps2).unwrap();
    
    Ok(())

}


fn server_exchange_mex(stream: &mut TcpStream, associated_data: &[u8], server_pk: &<Kem as KemTrait>::PublicKey) -> Result<(), Error> {
    
    let mut received = [0 as u8; 1];

    loop {
        // Testo che deve essere mandato criptato
        println!("\nInserisci testo");
        let mut input = String::new();
        io::stdin().read_line(&mut input).expect("Failed to read");

        // Let the client send a message to the server using the server's pubkey
        let (encapped_key, ciphertext, tag) =   
            client_encrypt_msg(
                input.as_bytes(), 
                associated_data, 
                &server_pk
            );
        

        // ##### CREAZIONE DEI PACCHETTI EncappedKey, Ciphertext, AssociatedData, TagBytes #####

        // => EncappedKey
        let ek = encapped_key.to_bytes().to_vec();
        let ek_pack = data_packets_manager::create_packet(
            data_packets_manager::DataType::EncappedKey, 
            ek
        );
        let ek_data_pack = ek_pack.group();
        let ek_data_pack_bytes = ek_data_pack.as_slice();

        // => ChiperText
        let ct_clone = ciphertext.clone();
        let ct_pack = data_packets_manager::create_packet(
            data_packets_manager::DataType::Ciphertext, 
            ct_clone
        );
        let ct_data_pack = ct_pack.group();
        let ct_data_pack_bytes = ct_data_pack.as_slice();

        // => AssociatedData
        let ad = associated_data.to_vec();
        let ad_pack = data_packets_manager::create_packet(
            data_packets_manager::DataType::AssociatedData, 
            ad
        );
        let ad_data_pack = ad_pack.group();
        let ad_data_pack_bytes = ad_data_pack.as_slice();

        // => TagBytes
        let tb = tag.to_bytes().to_vec();
        let tb_pack = data_packets_manager::create_packet(
            data_packets_manager::DataType::TagBytes, 
            tb
        );
        let tb_data_pack = tb_pack.group();
        let tb_data_pack_bytes = tb_data_pack.as_slice();


        // ##### INVIO DEI PACCHETTI EncappedKey, Ciphertext, AssociatedData, TagBytes #####

        println!("\nInvio pacchetti al server...\n");

        // => EncappedKey
        send_packet(stream, ek_data_pack_bytes, &mut received, String::from("EncappedKey"));
        display_pack(ek_data_pack_bytes);

        // => ChiperText
        send_packet(stream, ct_data_pack_bytes, &mut received, String::from("Ciphertext"));
        display_pack(ct_data_pack_bytes);

        // => AssociatedData             
        send_packet(stream, ad_data_pack_bytes, &mut received, String::from("AssociatedData"));
        display_pack(ad_data_pack_bytes);

        // => TagBytes              
        send_packet(stream, tb_data_pack_bytes, &mut received, String::from("Tag"));
        display_pack(tb_data_pack_bytes);

        // ##### RICEZIONE CONTENUTO MANDATO #####
        let mut buf = [0 as u8; 100];
        let bytes_read = stream.read(&mut buf);
        let mut msg = buf.to_vec();
        let msg = str::from_utf8(&msg).unwrap();
        println!("Il server ha inviato: {}", msg);

    }
    Ok(())
}


fn main() {

    //Generazione di chiave pubblica e privata del client
    let (client_prikey, client_pubkey) = client_init();
    
    let remote: SocketAddr = "127.0.0.1:8888".parse().unwrap();

    let kem_cps_av = ciphersuite_client::KEMtypeS::to_vect();
    let kdf_cps_av = ciphersuite_client::KDFtypeS::to_vect();
    let aead_cps_av = ciphersuite_client::AEADtypeS::to_vect();

    let mut server_pubkey:Vec<u8> = vec![];

    let mut kem_str:String = String::from("");
    let mut kdf_str:String = String::from("");
    let mut aead_str:String = String::from("");

    let associated_data = b"associated data"; 
       
    match TcpStream::connect(remote) {

        Ok(mut stream) => {

            /*Primary client initiates a request to the primary server. 
              The request contains a list of available ciphersuites for KEM, KDF, and AEAD. */
            handle_server(
                remote,
                &mut stream, 
                &mut server_pubkey, 
                &mut kem_str, 
                &mut kdf_str, 
                &mut aead_str,
                &kem_cps_av,
                &kdf_cps_av,
                &aead_cps_av
            ).unwrap();
            
            println!("kem scelto: {}", kem_str);
            println!("kdf scelto: {}", kdf_str);
            println!("aead scelto: {}", aead_str);
    
            // Recupera la serve public key
            let server_pubkey = <Kem as KemTrait>::PublicKey::from_bytes(
                &mut server_pubkey.as_slice()
            ).expect("could not deserialize the encapsulated pubkey!");

            server_exchange_mex(
                &mut stream, 
                associated_data, 
                &server_pubkey
            ).unwrap();
       },

        Err(e) => {
            println!("Fallimento nel connettersi: {}", e);
            return;
        },
    }

}