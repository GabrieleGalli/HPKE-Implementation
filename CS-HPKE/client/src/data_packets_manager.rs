use hpke::Kem as KemTrait;

use crate::Kem;

pub enum DataType<'a> {
    EncappedKey(&'a <Kem as KemTrait>::EncappedKey),
    Ciphertext(&'a Vec<u8>),
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
    pub(crate) payload: Vec<u8>,
}

impl DataPacket {
    pub fn to_bytes(&self) -> Vec<u8> {
        let header_clone = self.header.clone();
        let mut payload_clone = self.payload.clone();
        payload_clone.push(header_clone);
        payload_clone
    }
}