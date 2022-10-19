
pub const ID_POS_HEADER:        usize   = 0;    // position of the ID in the header 
pub const PROT_POS_HEADER:      usize   = 1;    // position of the utf data type in the header 
pub const DATALEN_POS_HEADER:   usize   = 2;    // position of the payload length in the header
pub const DATA_START_POS:       usize   = 3;    // position of the firt payload element 


pub struct Header {
    data_type: u8,
    protocol: u8,
    data_len: usize
}

pub struct DataPack {
    header: Header,
    payload: Vec<u8>
}

pub fn create_pack(utf: u8, dtype: u8, data: Vec<u8>) -> DataPack {
    let h = Header {
        data_type: dtype,
        protocol: utf,
        data_len: data.len()
    };
    let pack = DataPack {
        header: h,
        payload: data
    };
    pack
}

// dato un vettore dati, rende riferimento a un buffer pronto a essere inviato
pub fn pack_as_vect(data: Vec<u8>, utf: u8, dtype: u8) -> Vec<u8> {
    let pack = create_pack(utf, dtype, data);
    let pack = pack.group();
    pack
}

impl DataPack {
    pub fn group(&self) -> Vec<u8> {
        // Organizza in un unico vettore l'intero pacchetto
        let mut output = vec![];
        output.push(self.header.data_type);
        output.push(self.header.protocol);
        output.push(self.header.data_len.try_into().unwrap());
        for a in &self.payload {
            output.push(*a);
        }
        output
    }
}