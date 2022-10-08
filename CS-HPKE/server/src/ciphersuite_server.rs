use std::fmt;
use strum::IntoEnumIterator; 
use strum_macros::EnumIter; 


//######################### KEM ###############################
#[derive(Debug, EnumIter)]
pub enum KEMtypeR {
    // Algoritmi per KEM disponibili
    X25519HkdfSha256, 
    //DhP256HkdfSha256
}
// implementazione di Display per stampare gli id degli algoritmi
impl fmt::Display for KEMtypeR {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            KEMtypeR::X25519HkdfSha256 => write!(f, "0x0010"),
            //KEMtypeR::DhP256HkdfSha256 => write!(f, "0x0020"),
        }
    }
}
// racchiude in un unico vettore gli algoritmi (stringhe) disponibili
impl KEMtypeR {
    pub fn to_vect() -> Vec<String> {
        let mut vect = vec![];
        for i in KEMtypeR::iter() {
            vect.push(i.to_string());
        }
        vect
    }
}

//######################### KDF ###############################
#[derive(Debug, EnumIter)]
pub enum KDFtypeR {
    // Algoritmi per KEM disponibili
    HkdfSha256, 
    //HkdfSha384, 
    HkdfSha512
}
// implementazione di Display per stampare gli id degli algoritmi
impl fmt::Display for KDFtypeR {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            KDFtypeR::HkdfSha256 => write!(f, "0x0001"),
            //KDFtypeR::HkdfSha384 => write!(f, "0x0002"),
            KDFtypeR::HkdfSha512 => write!(f, "0x0003"),
        }
    }
}
// racchiude in un unico vettore gli algoritmi (stringhe) disponibili
impl KDFtypeR {
    pub fn to_vect() -> Vec<String> {
        let mut vect = vec![];
        for i in KDFtypeR::iter() {
            vect.push(i.to_string());
        }
        vect
    }
}

//######################### AEAD ##############################
#[derive(Debug, EnumIter)]
pub enum AEADtypeR {
    // Algoritmi per KEM disponibili
    AesGcm128, 
    //AesGcm256, 
    //ChaCha20Poly1305, 
    //ExportOnlyAead
}
// implementazione di Display per stampare gli id degli algoritmi
impl fmt::Display for AEADtypeR {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AEADtypeR::AesGcm128 => write!(f, "0x0001"),
            //AEADtypeR::AesGcm256 => write!(f, "0x0002"),
            //AEADtypeR::ChaCha20Poly1305 => write!(f, "0x0003"),
            //AEADtypeR::ExportOnlyAead => write!(f, "0xFFFF"),
        }
    }
}
// racchiude in un unico vettore gli algoritmi (stringhe) disponibili
impl AEADtypeR {
    pub fn to_vect() -> Vec<String> {
        let mut vect = vec![];
        for i in AEADtypeR::iter() {
            vect.push(i.to_string());
        }
        vect
    }
}