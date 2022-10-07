use hpke::Kem as KemTrait;
use crate::Kem;

// Tipi di dati che devono essere scambiati tra client e server
pub enum DataType {
    PublicKey,
    EncappedKey,
    Ciphertext,
    AssociatedData,
    TagBytes,
    Enc_ctx_KEM,
    Enc_ctx_KDF,
    Enc_ctx_AEAD
}

// Ogni DataType viene riconosciuto tramite un numero intero (1° elemento nel pacchetto)
pub fn datatype_to_int(data_ype: &DataType) -> u8 {
    match data_ype {
        DataType::PublicKey => 0,
        DataType::EncappedKey => 1,
        DataType::Ciphertext => 2,
        DataType::AssociatedData => 3,
        DataType::TagBytes => 4,
        DataType::Enc_ctx_KEM => 5,
        DataType::Enc_ctx_KDF => 6,
        DataType::Enc_ctx_AEAD => 7
    }
}

// Rende un Datatype da un numero intero
pub fn int_to_datatype(i:u8) -> DataType {
    if i == 0 {
        DataType::PublicKey
    } else if i == 1 {
        DataType::EncappedKey
    } else if i == 2 {
        DataType::Ciphertext
    } else if i == 3 {
        DataType::AssociatedData
    } else if i == 4 {
        DataType::TagBytes
    } else if i == 5 {
        DataType::Enc_ctx_KEM
    } else if i == 6 {
        DataType::Enc_ctx_KDF
    } else {
        DataType::Enc_ctx_AEAD
    }
}

// Rende un elemento di DataType printabile da un numero intero
pub fn int_to_datatype_display(i:u8) -> String {
    if i == 0 {
        String::from("PublicKey")
    } else if i == 1 {
        String::from("EncappedKey")
    } else if i == 2 {
        String::from("CipherText")
    } else if i == 3 {
        String::from("AssociatedData")
    } else if i == 4 {
        String::from("TagBytes")
    } else if i == 5 {
        String::from("Enc_ctx_KEM")
    } else if i == 6 {
        String::from("Enc_ctx_KDF")
    } else {
        String::from("Enc_ctx_AEAD")
    }
}
 
// Header del pacchetto: [DataType|Len]
pub struct HeaderData {
    data_type: DataType,
    data_len: usize
}

// Pacchetto: [Header|Payload]
pub struct DataPacket {
    header: HeaderData,
    payload: Vec<u8>
}

impl DataPacket {
    // Organizza in un unico vettore l'intero pacchetto
    pub fn group(&self) -> Vec<u8> {
        // Restituisce un vec<u8>: header|payload
        let pack_id = datatype_to_int(&self.header.data_type);
        let len = self.payload.len();

        let mut payload_clone = self.payload.clone();

        payload_clone.insert(0, len.try_into().unwrap());
        payload_clone.insert(0, pack_id);
        
        payload_clone
    }
}

// Crea un pacchetto
pub fn create_packet(dt: DataType, data: Vec<u8>) -> DataPacket {
    let head = HeaderData {
        data_type: dt,
        data_len: data.len()
    };
    let data_pack = DataPacket {
        header: head,
        payload: data
    };
    data_pack
}