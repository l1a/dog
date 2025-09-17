use log::*;

use crate::wire::*;

/// A **DNSKEY** record, which contains a public key for DNSSEC.
///
/// # References
///
/// - [RFC 4034](https://tools.ietf.org/html/rfc4034) — Resource Records for the DNS Security Extensions (March 2005)
#[derive(PartialEq, Debug)]
pub struct DNSKEY {
    /// The flags field indicates the key's properties.
    pub flags: u16,

    /// The protocol field must be set to 3.
    pub protocol: u8,

    /// The algorithm field indicates the algorithm used to generate the key.
    pub algorithm: u8,

    /// The public key itself.
    pub public_key: Vec<u8>,
}

impl Wire for DNSKEY {
    const NAME: &'static str = "DNSKEY";
    const RR_TYPE: u16 = 48;

    #[cfg_attr(feature = "with_mutagen", ::mutagen::mutate)]
    fn read(stated_length: u16, c: &mut Cursor<&[u8]>) -> Result<Self, WireError> {
        let flags = c.read_u16::<BigEndian>()?;
        trace!("Parsed flags -> {:?}", flags);

        let protocol = c.read_u8()?;
        trace!("Parsed protocol -> {:?}", protocol);

        let algorithm = c.read_u8()?;
        trace!("Parsed algorithm -> {:?}", algorithm);

        let public_key_len = stated_length - 4;
        let mut public_key = vec![];
        for _ in 0..public_key_len {
            public_key.push(c.read_u8()?);
        }
        trace!("Parsed public_key -> {:?}", public_key);

        Ok(Self { flags, protocol, algorithm, public_key })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn parses() {
        let buf = &[
            0x00, 0x01,  // flags
            0x03,        // protocol
            0x05,        // algorithm
            0x12, 0x34, 0x56, 0x78,  // public_key (4 bytes for example)
        ];

        assert_eq!(DNSKEY::read(buf.len() as _, &mut Cursor::new(buf)).unwrap(),
                   DNSKEY {
                       flags: 1,
                       protocol: 3,
                       algorithm: 5,
                       public_key: vec![0x12, 0x34, 0x56, 0x78],
                   });
    }

    #[test]
    fn record_empty() {
        assert_eq!(DNSKEY::read(0, &mut Cursor::new(&[])),
                   Err(WireError::IO));
    }

    #[test]
    fn buffer_ends_abruptly() {
        let buf = &[
            0x00,  // half a flags
        ];

        assert_eq!(DNSKEY::read(6, &mut Cursor::new(buf)),
                   Err(WireError::IO));
    }
}
