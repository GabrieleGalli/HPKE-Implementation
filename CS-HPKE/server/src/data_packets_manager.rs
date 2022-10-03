use hpke::Kem as KemTrait;
use crate::Kem;

// Tipi di dati che devono essere scambiati tra client e server
pub enum DataType {
    EncappedKey,
    Ciphertext,
    AssociatedData,
    TagBytes
}

// Ogni DataType viene riconosciuto tramite un numero intero (1° elemento nel pacchetto)
pub fn data_type_int(data_ype: &DataType) -> u8 {
    match data_ype {
        DataType::EncappedKey => 1,
        DataType::Ciphertext => 2,
        DataType::AssociatedData => 3,
        DataType::TagBytes => 4,
    }
}

// Rende un Datatype da un numero intero
pub fn int_data_type(i:u8) -> DataType {
    if i == 1 {
        DataType::EncappedKey
    } else if i == 2 {
        DataType::Ciphertext
    } else if i == 3 {
        DataType::AssociatedData
    } else {
        DataType::TagBytes
    }
}

// Rende un elemento di DataType printabile da un numero intero
pub fn int_data_type_display(i:u8) -> String {
    if i == 1 {
        String::from("EncappedKey")
    } else if i == 2 {
        String::from("CipherText")
    } else if i == 3 {
        String::from("AssociatedData")
    } else {
        String::from("TagBytes")
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
        // Restituisce un vec<u8>: heder|payload
        let pack_id = data_type_int(&self.header.data_type);
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