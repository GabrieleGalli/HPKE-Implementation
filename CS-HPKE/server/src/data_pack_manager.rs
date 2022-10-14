pub const ID_POS_HEADER: usize = 0;         // position of the ID in the header 
pub const DATALEN_POS_HEADER: usize = 1;    // position of the payload length in the header
pub const DATA_START_POS:usize = 2;         // position of the firt payload element

pub struct Header {
    data_type: u8,
    data_len: usize
}

pub struct DataPack {
    header: Header,
    payload: Vec<u8>
}

pub fn create_pack(dtype: u8, data: Vec<u8>) -> DataPack {
    let h = Header {
        data_type: dtype,
        data_len: data.len()
    };
    let pack = DataPack {
        header: h,
        payload: data
    };
    pack
}

impl DataPack {
    pub fn group(&self) -> Vec<u8> {
        // Organizza in un unico vettore l'intero pacchetto
        let mut output = vec![];
        output.push(self.header.data_type);
        output.push(self.header.data_len.try_into().unwrap());
        for a in &self.payload {
            output.push(*a);
        }
        output
    }
    
}