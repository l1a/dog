use log::*;

use crate::wire::*;

/// A **NSEC3PARAM** record, which contains the parameters used for NSEC3 records in the zone.
///
/// # References
///
/// - [RFC 5155](https://tools.ietf.org/html/rfc5155) — DNS Security (DNSSEC) Hashed Authenticated Denial of Existence (March 2008)
#[derive(PartialEq, Debug)]
pub struct NSEC3PARAM {
    /// The hash algorithm used for hashing the owner name.
    pub hash_algorithm: u8,

    /// Flags for the NSEC3PARAM record.
    pub flags: u8,

    /// The number of iterations of the hash function.
    pub iterations: u16,

    /// The salt used in the hash computation.
    pub salt: Vec<u8>,
}

impl Wire for NSEC3PARAM {
    const NAME: &'static str = "NSEC3PARAM";
    const RR_TYPE: u16 = 51;

    #[cfg_attr(feature = "with_mutagen", ::mutagen::mutate)]
    fn read(stated_length: u16, c: &mut Cursor<&[u8]>) -> Result<Self, WireError> {
        let hash_algorithm = c.read_u8()?;
        trace!("Parsed hash_algorithm -> {:?}", hash_algorithm);

        let flags = c.read_u8()?;
        trace!("Parsed flags -> {:?}", flags);

        let iterations = c.read_u16::<BigEndian>()?;
        trace!("Parsed iterations -> {:?}", iterations);

        let salt_length = c.read_u8()? as usize;
        let mut salt = vec![];
        for _ in 0..salt_length {
            salt.push(c.read_u8()?);
        }
        trace!("Parsed salt -> {:?}", salt);

        let length_after_fields = 1 + 1 + 2 + 1 + salt_length as u16;
        if stated_length == length_after_fields {
            trace!("Length is correct");
            Ok(Self { hash_algorithm, flags, iterations, salt })
        } else {
            warn!("Length is incorrect (stated length {:?}, fields plus salt length {:?})", stated_length, length_after_fields);
            Err(WireError::WrongLabelLength { stated_length, length_after_labels: length_after_fields })
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn parses() {
        let buf = &[
            0x01,        // hash_algorithm
            0x00,        // flags
            0x00, 0x01,  // iterations
            0x04,        // salt_length
            0x11, 0x22, 0x33, 0x44,  // salt
        ];

        assert_eq!(NSEC3PARAM::read(buf.len() as _, &mut Cursor::new(buf)).unwrap(),
                   NSEC3PARAM {
                       hash_algorithm: 1,
                       flags: 0,
                       iterations: 1,
                       salt: vec![0x11, 0x22, 0x33, 0x44],
                   });
    }

    #[test]
    fn record_empty() {
        assert_eq!(NSEC3PARAM::read(0, &mut Cursor::new(&[])),
                   Err(WireError::IO));
    }

    #[test]
    fn buffer_ends_abruptly() {
        let buf = &[
            0x01,  // hash_algorithm
        ];

        assert_eq!(NSEC3PARAM::read(10, &mut Cursor::new(buf)),
                   Err(WireError::IO));
    }
}
