use hpke::Kem as KemTrait;

use crate::Kem;

pub enum DataType {
    EncappedKey(<Kem as KemTrait>::EncappedKey),
    Ciphertext(Vec<u8>),
    AssociatedData,
    TagBytes,
}

pub fn data_type_int(data_ype: DataType) -> u8 {
    match data_ype {
        DataType::EncappedKey(_) => 1,
        DataType::Ciphertext(_) => 2,
        DataType::AssociatedData => 3,
        DataType::TagBytes => 4,
    }
}

pub struct DataPacket {
    pub(crate) header: u8,
    pub(crate) payload: Vec<u8>
}

impl DataPacket {
    pub fn group(&self) -> Vec<u8> {
        // Restituisce un vec<u8>: heder|payload
        let header_clone = self.header.clone();
        let mut payload_clone = self.payload.clone();
        payload_clone.insert(0, header_clone);
        payload_clone
    }
}