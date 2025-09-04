use std::io::Write;

use bcder::{
    encode::{self, Values},
    Mode, OctetString,
};
use ring::digest::{self, SHA256};

use crate::{rfc5280::AlgorithmIdentifier, DigestAlgorithm};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ESSCertIDv2 {
    pub hash_algorithm: AlgorithmIdentifier,
    pub cert_hash: OctetString,
    // issuerSerial opcional lo omito por simplicidad
}

impl ESSCertIDv2 {
    pub fn encode_ref(&self) -> impl Values + '_ {
        // AlgorithmIdentifier ya implementa Values, OctetString tiene encode_ref()
        encode::sequence((&self.hash_algorithm, self.cert_hash.encode_ref()))
    }

    // helper si quieres bytes DER individuales del elemento
    pub fn to_der_bytes(&self) -> Vec<u8> {
        let mut v = Vec::new();
        self.encode_ref().write_encoded(Mode::Der, &mut v).unwrap();
        v
    }
}

/// Tipo auxiliar que implementa `Values` para un `SEQUENCE OF ESSCertIDv2`.
struct SequenceOfESS<'a> {
    elems: &'a [ESSCertIDv2],
}

impl<'a> Values for SequenceOfESS<'a> {
    fn encoded_len(&self, mode: Mode) -> usize {
        // longitud del contenido: suma de longitudes de cada elemento (ya con su tag/len)
        let content_len: usize = self
            .elems
            .iter()
            .map(|e| e.encode_ref().encoded_len(mode))
            .sum();

        // calcular longitud en bytes del campo "length" de ASN.1
        let len_len = if content_len < 128 {
            1usize
        } else {
            let mut n = content_len;
            let mut bytes = 0usize;
            while n > 0 {
                bytes += 1;
                n >>= 8;
            }
            1 + bytes // 1 byte inicial con 0x80 | nbytes + nbytes
        };

        // 1 byte tag (0x30) + len_len + content_len
        1 + len_len + content_len
    }

    fn write_encoded<W: Write>(&self, mode: Mode, target: &mut W) -> Result<(), std::io::Error> {
        // escribir tag SEQUENCE (universal, constructed, tag=16 -> 0x30)
        target.write_all(&[0x30])?;

        let content_len: usize = self
            .elems
            .iter()
            .map(|e| e.encode_ref().encoded_len(mode))
            .sum();

        // escribir longitud en forma DER
        if content_len < 128 {
            target.write_all(&[content_len as u8])?;
        } else {
            // big-endian length bytes
            let mut len_bytes = Vec::new();
            let mut n = content_len;
            while n > 0 {
                len_bytes.push((n & 0xFF) as u8);
                n >>= 8;
            }
            len_bytes.reverse();
            target.write_all(&[0x80 | (len_bytes.len() as u8)])?;
            target.write_all(&len_bytes)?;
        }

        // escribir cada elemento codificado
        for e in self.elems.iter() {
            e.encode_ref().write_encoded(mode, target)?;
        }

        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SigningCertificateV2 {
    pub certs: Vec<ESSCertIDv2>,
    // policies opcional omitido por ahora
}

impl SigningCertificateV2 {
    pub fn encode_ref(&self) -> impl Values + '_ {
        // El primer (y único) campo es "certs" que es SEQUENCE OF ESSCertIDv2
        // lo construimos pasando nuestro SequenceOfESS (que implementa Values)
        encode::sequence((SequenceOfESS { elems: &self.certs },))
    }

    /// Si prefieres obtener los bytes DER ya listos:
    pub fn to_der(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode_ref()
            .write_encoded(Mode::Der, &mut out)
            .unwrap();
        out
    }
}

pub fn build_ess_signing_cert_v2(cert_der: &[u8]) -> SigningCertificateV2 {
    // Crear AlgorithmIdentifier OID SHA1
    // let oid_sha256 = rasn::types::ObjectIdentifier::new(&[2, 16, 840, 1, 101, 3, 4, 2, 1]).unwrap();
    let hash_algorithm = AlgorithmIdentifier {
        algorithm: DigestAlgorithm::Sha256.into(),
        parameters: None,
    };

    let hash = digest::digest(&SHA256, cert_der);

    let ess = ESSCertIDv2 {
        hash_algorithm: hash_algorithm,
        cert_hash: OctetString::new(hash.as_ref().to_vec().into()),
    };

    let scv2 = SigningCertificateV2 { certs: vec![ess] };

    scv2
}
