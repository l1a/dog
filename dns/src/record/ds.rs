use log::*;

use crate::wire::*;

/// A **DS** record, which contains a delegation signer for DNSSEC.
///
/// # References
///
/// - [RFC 4034](https://tools.ietf.org/html/rfc4034) — Resource Records for the DNS Security Extensions (March 2005)
#[derive(PartialEq, Debug)]
pub struct DS {
    /// The key tag of the DNSKEY RR that the DS record refers to.
    pub key_tag: u16,

    /// The algorithm number of the DNSKEY RR that the DS record refers to.
    pub algorithm: u8,

    /// The algorithm used to construct the digest.
    pub digest_type: u8,

    /// The digest of the DNSKEY RR.
    pub digest: Vec<u8>,
}

impl Wire for DS {
    const NAME: &'static str = "DS";
    const RR_TYPE: u16 = 43;

    #[cfg_attr(feature = "with_mutagen", ::mutagen::mutate)]
    fn read(stated_length: u16, c: &mut Cursor<&[u8]>) -> Result<Self, WireError> {
        let key_tag = c.read_u16::<BigEndian>()?;
        trace!("Parsed key_tag -> {:?}", key_tag);

        let algorithm = c.read_u8()?;
        trace!("Parsed algorithm -> {:?}", algorithm);

        let digest_type = c.read_u8()?;
        trace!("Parsed digest_type -> {:?}", digest_type);

        let digest_len = stated_length - 4;
        let mut digest = vec![];
        for _ in 0..digest_len {
            digest.push(c.read_u8()?);
        }
        trace!("Parsed digest -> {:?}", digest);

        Ok(Self { key_tag, algorithm, digest_type, digest })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn parses() {
        let buf = &[
            0x00, 0x01,  // key_tag
            0x05,        // algorithm
            0x01,        // digest_type
            0x12, 0x34, 0x56, 0x78,  // digest (4 bytes for example)
        ];

        assert_eq!(DS::read(buf.len() as _, &mut Cursor::new(buf)).unwrap(),
                   DS {
                       key_tag: 1,
                       algorithm: 5,
                       digest_type: 1,
                       digest: vec![0x12, 0x34, 0x56, 0x78],
                   });
    }

    #[test]
    fn record_empty() {
        assert_eq!(DS::read(0, &mut Cursor::new(&[])),
                   Err(WireError::IO));
    }

    #[test]
    fn buffer_ends_abruptly() {
        let buf = &[
            0x00,  // half a key_tag
        ];

        assert_eq!(DS::read(6, &mut Cursor::new(buf)),
                   Err(WireError::IO));
    }
}
