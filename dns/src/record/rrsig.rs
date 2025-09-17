use log::*;

use crate::strings::{Labels, ReadLabels};
use crate::wire::*;

/// A **RRSIG** record, which contains a digital signature for DNSSEC.
///
/// # References
///
/// - [RFC 4034](https://tools.ietf.org/html/rfc4034) — Resource Records for the DNS Security Extensions (March 2005)
#[derive(PartialEq, Debug)]
pub struct RRSIG {
    /// The type of RRset covered by this signature.
    pub type_covered: u16,

    /// The cryptographic algorithm used to generate the signature.
    pub algorithm: u8,

    /// The number of labels in the original RRSIG RR owner name.
    pub labels: u8,

    /// The TTL of the RRset covered by this signature.
    pub original_ttl: u32,

    /// The expiration date of the signature.
    pub signature_expiration: u32,

    /// The inception date of the signature.
    pub signature_inception: u32,

    /// The key tag of the key that generated the signature.
    pub key_tag: u16,

    /// The name of the entity that generated the signature.
    pub signers_name: Labels,

    /// The cryptographic signature.
    pub signature: Vec<u8>,
}

impl Wire for RRSIG {
    const NAME: &'static str = "RRSIG";
    const RR_TYPE: u16 = 46;

    #[cfg_attr(feature = "with_mutagen", ::mutagen::mutate)]
    fn read(stated_length: u16, c: &mut Cursor<&[u8]>) -> Result<Self, WireError> {
        let type_covered = c.read_u16::<BigEndian>()?;
        trace!("Parsed type_covered -> {:?}", type_covered);

        let algorithm = c.read_u8()?;
        trace!("Parsed algorithm -> {:?}", algorithm);

        let labels = c.read_u8()?;
        trace!("Parsed labels -> {:?}", labels);

        let original_ttl = c.read_u32::<BigEndian>()?;
        trace!("Parsed original_ttl -> {:?}", original_ttl);

        let signature_expiration = c.read_u32::<BigEndian>()?;
        trace!("Parsed signature_expiration -> {:?}", signature_expiration);

        let signature_inception = c.read_u32::<BigEndian>()?;
        trace!("Parsed signature_inception -> {:?}", signature_inception);

        let key_tag = c.read_u16::<BigEndian>()?;
        trace!("Parsed key_tag -> {:?}", key_tag);

        let (signers_name, signers_name_length) = c.read_labels()?;
        trace!("Parsed signers_name -> {:?}", signers_name);

        let signature_len = stated_length - (2 + 1 + 1 + 4 + 4 + 4 + 2 + signers_name_length);
        let mut signature = vec![];
        for _ in 0..signature_len {
            signature.push(c.read_u8()?);
        }
        trace!("Parsed signature -> {:?}", signature);

        Ok(Self {
            type_covered,
            algorithm,
            labels,
            original_ttl,
            signature_expiration,
            signature_inception,
            key_tag,
            signers_name,
            signature,
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn parses() {
        let buf = &[
            0x00, 0x01,  // type_covered
            0x05,        // algorithm
            0x03,        // labels
            0x00, 0x00, 0x00, 0x01,  // original_ttl
            0x00, 0x00, 0x00, 0x02,  // signature_expiration
            0x00, 0x00, 0x00, 0x03,  // signature_inception
            0x00, 0x04,  // key_tag
            0x03, 0x64, 0x6e, 0x73,  // signers_name (example: dns)
            0x00,                    // signers_name terminator
            0x12, 0x34, 0x56,  // signature (3 bytes for example)
        ];

        assert_eq!(RRSIG::read(buf.len() as _, &mut Cursor::new(buf)).unwrap(),
                   RRSIG {
                       type_covered: 1,
                       algorithm: 5,
                       labels: 3,
                       original_ttl: 1,
                       signature_expiration: 2,
                       signature_inception: 3,
                       key_tag: 4,
                       signers_name: Labels::encode("dns").unwrap(),
                       signature: vec![0x12, 0x34, 0x56],
                   });
    }

    #[test]
    fn record_empty() {
        assert_eq!(RRSIG::read(0, &mut Cursor::new(&[])),
                   Err(WireError::IO));
    }

    #[test]
    fn buffer_ends_abruptly() {
        let buf = &[
            0x00,  // half a type_covered
        ];

        assert_eq!(RRSIG::read(20, &mut Cursor::new(buf)),
                   Err(WireError::IO));
    }
}
