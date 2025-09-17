use log::*;

use crate::strings::{Labels, ReadLabels};
use crate::wire::*;

/// A **NSEC** record, which specifies that types listed in the type bit maps field do not exist for the domain name.
///
/// # References
///
/// - [RFC 4034](https://tools.ietf.org/html/rfc4034) — Resource Records for the DNS Security Extensions (March 2005)
#[derive(PartialEq, Debug)]
pub struct NSEC {
    /// The name of the next domain in the canonical ordering of the zone.
    pub next_domain_name: Labels,

    /// The type bit maps field contains the list of RR types present at the NSEC RR's owner name.
    pub type_bit_maps: Vec<u8>,
}

impl Wire for NSEC {
    const NAME: &'static str = "NSEC";
    const RR_TYPE: u16 = 47;

    #[cfg_attr(feature = "with_mutagen", ::mutagen::mutate)]
    fn read(stated_length: u16, c: &mut Cursor<&[u8]>) -> Result<Self, WireError> {
        let (next_domain_name, next_domain_name_length) = c.read_labels()?;
        trace!("Parsed next_domain_name -> {:?}", next_domain_name);

        let type_bit_maps_len = stated_length - next_domain_name_length;
        let mut type_bit_maps = vec![];
        for _ in 0..type_bit_maps_len {
            type_bit_maps.push(c.read_u8()?);
        }
        trace!("Parsed type_bit_maps -> {:?}", type_bit_maps);

        Ok(Self { next_domain_name, type_bit_maps })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn parses() {
        let buf = &[
            0x03, 0x64, 0x6e, 0x73,  // next_domain_name (example: dns)
            0x00,                    // next_domain_name terminator
            0x00, 0x01, 0x02,        // type_bit_maps (3 bytes for example)
        ];

        assert_eq!(NSEC::read(buf.len() as _, &mut Cursor::new(buf)).unwrap(),
                   NSEC {
                       next_domain_name: Labels::encode("dns").unwrap(),
                       type_bit_maps: vec![0x00, 0x01, 0x02],
                   });
    }

    #[test]
    fn record_empty() {
        assert_eq!(NSEC::read(0, &mut Cursor::new(&[])),
                   Err(WireError::IO));
    }

    #[test]
    fn buffer_ends_abruptly() {
        let buf = &[
            0x03, 0x64,  // half a next_domain_name
        ];

        assert_eq!(NSEC::read(10, &mut Cursor::new(buf)),
                   Err(WireError::IO));
    }
}
