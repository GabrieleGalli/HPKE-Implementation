use crate::agility:: {KemAlg, KdfAlg, AeadAlg};


pub fn supported_kem_algs() -> &'static [KemAlg] {
    return &[
        KemAlg::X25519HkdfSha256, 
        KemAlg::DhP256HkdfSha256,
    ];
}

pub fn supported_kdf_algs() -> &'static [KdfAlg] {
    return &[
        KdfAlg::HkdfSha256, 
        KdfAlg::HkdfSha384, 
        KdfAlg::HkdfSha512,
    ];
}

pub fn supported_aead_algs() -> &'static [AeadAlg] {
    return &[
        AeadAlg::AesGcm128,
        AeadAlg::AesGcm256,
        AeadAlg::ChaCha20Poly1305,
    ];
}