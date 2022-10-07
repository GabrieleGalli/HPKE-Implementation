use std::fmt;
use strum::IntoEnumIterator; 
use strum_macros::EnumIter; 


//######################### KEM ###############################
#[derive(Debug, EnumIter)]
pub enum KEMtypeS {
    // Algoritmi per KEM disponibili
    X25519HkdfSha256, 
    DhP256HkdfSha256
}
// implementazione di Display per stampare gli id degli algoritmi
impl fmt::Display for KEMtypeS {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            KEMtypeS::X25519HkdfSha256 => write!(f, "0x0010"),
            KEMtypeS::DhP256HkdfSha256 => write!(f, "0x0020"),
        }
    }
}
// racchiude in un unico vettore gli algoritmi (stringhe) disponibili
impl KEMtypeS {
    pub fn to_vect() -> Vec<String> {
        let mut vect = vec![];
        for i in KEMtypeS::iter() {
            vect.push(i.to_string());
        }
        vect
    }
}

//######################### KDF ###############################
#[derive(Debug, EnumIter)]
pub enum KDFtypeS {
    // Algoritmi per KEM disponibili
    HkdfSha256, 
    HkdfSha384, 
    HkdfSha512
}
// implementazione di Display per stampare gli id degli algoritmi
impl fmt::Display for KDFtypeS {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            KDFtypeS::HkdfSha256 => write!(f, "0x0001"),
            KDFtypeS::HkdfSha384 => write!(f, "0x0002"),
            KDFtypeS::HkdfSha512 => write!(f, "0x0003"),
        }
    }
}
// racchiude in un unico vettore gli algoritmi (stringhe) disponibili
impl KDFtypeS {
    pub fn to_vect() -> Vec<String> {
        let mut vect = vec![];
        for i in KDFtypeS::iter() {
            vect.push(i.to_string());
        }
        vect
    }
}

//######################### AEAD ##############################
#[derive(Debug, EnumIter)]
pub enum AEADtypeS {
    // Algoritmi per KEM disponibili
    AesGcm128, 
    AesGcm256, 
    ChaCha20Poly1305, 
    ExportOnlyAead
}
// implementazione di Display per stampare gli id degli algoritmi
impl fmt::Display for AEADtypeS {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AEADtypeS::AesGcm128 => write!(f, "0x0001"),
            AEADtypeS::AesGcm256 => write!(f, "0x0002"),
            AEADtypeS::ChaCha20Poly1305 => write!(f, "0x0003"),
            AEADtypeS::ExportOnlyAead => write!(f, "0xFFFF"),
        }
    }
}
// racchiude in un unico vettore gli algoritmi (stringhe) disponibili
impl AEADtypeS {
    pub fn to_vect() -> Vec<String> {
        let mut vect = vec![];
        for i in AEADtypeS::iter() {
            vect.push(i.to_string());
        }
        vect
    }
}