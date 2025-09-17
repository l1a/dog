use log::*;

use crate::wire::*;

/// A **DHCID** record, which identifies the client to the DHCP server for DNS updates.
///
/// # References
///
/// - [RFC 4701](https://tools.ietf.org/html/rfc4701) — A DNS Resource Record (RR) for Encoding DHCP Information (October 2006)
#[derive(PartialEq, Debug)]
pub struct DHCID {
    /// The identifier type code, indicating how the client identifier was formed.
    pub identifier_type_code: u8,

    /// The digest type code, indicating the algorithm used to create the digest.
    pub digest_type_code: u8,

    /// The digest of the client identifier.
    pub digest: Vec<u8>,
}

impl Wire for DHCID {
    const NAME: &'static str = "DHCID";
    const RR_TYPE: u16 = 49;

    #[cfg_attr(feature = "with_mutagen", ::mutagen::mutate)]
    fn read(stated_length: u16, c: &mut Cursor<&[u8]>) -> Result<Self, WireError> {
        let identifier_type_code = c.read_u8()?;
        trace!("Parsed identifier_type_code -> {:?}", identifier_type_code);

        let digest_type_code = c.read_u8()?;
        trace!("Parsed digest_type_code -> {:?}", digest_type_code);

        let digest_len = stated_length - 2;
        let mut digest = vec![];
        for _ in 0..digest_len {
            digest.push(c.read_u8()?);
        }
        trace!("Parsed digest -> {:?}", digest);

        Ok(Self { identifier_type_code, digest_type_code, digest })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn parses() {
        let buf = &[
            0x00,        // identifier_type_code
            0x01,        // digest_type_code
            0x12, 0x34, 0x56, 0x78,  // digest (4 bytes for example)
        ];

        assert_eq!(DHCID::read(buf.len() as _, &mut Cursor::new(buf)).unwrap(),
                   DHCID {
                       identifier_type_code: 0,
                       digest_type_code: 1,
                       digest: vec![0x12, 0x34, 0x56, 0x78],
                   });
    }

    #[test]
    fn record_empty() {
        assert_eq!(DHCID::read(0, &mut Cursor::new(&[])),
                   Err(WireError::IO));
    }

    #[test]
    fn buffer_ends_abruptly() {
        let buf = &[
            0x00,  // only one byte
        ];

        assert_eq!(DHCID::read(4, &mut Cursor::new(buf)),
                   Err(WireError::IO));
    }
}
