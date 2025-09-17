use log::*;

use crate::wire::*;

/// A **NSEC3** record, which provides denial of existence for DNSSEC using hash of domain names.
///
/// # References
///
/// - [RFC 5155](https://tools.ietf.org/html/rfc5155) — DNS Security (DNSSEC) Hashed Authenticated Denial of Existence (March 2008)
#[derive(PartialEq, Debug)]
pub struct NSEC3 {
    /// The hash algorithm used for hashing the owner name.
    pub hash_algorithm: u8,

    /// Flags for the NSEC3 record.
    pub flags: u8,

    /// The number of iterations of the hash function.
    pub iterations: u16,

    /// The salt used in the hash computation.
    pub salt: Vec<u8>,

    /// The next hashed owner name in the canonical ordering.
    pub next_hashed_owner_name: Vec<u8>,

    /// The type bit maps field.
    pub type_bit_maps: Vec<u8>,
}

impl Wire for NSEC3 {
    const NAME: &'static str = "NSEC3";
    const RR_TYPE: u16 = 50;

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

        let hash_length = c.read_u8()? as usize;
        let mut next_hashed_owner_name = vec![];
        for _ in 0..hash_length {
            next_hashed_owner_name.push(c.read_u8()?);
        }
        trace!("Parsed next_hashed_owner_name -> {:?}", next_hashed_owner_name);

        let type_bit_maps_len = stated_length - (1 + 1 + 2 + 1 + salt_length as u16 + 1 + hash_length as u16);
        let mut type_bit_maps = vec![];
        for _ in 0..type_bit_maps_len {
            type_bit_maps.push(c.read_u8()?);
        }
        trace!("Parsed type_bit_maps -> {:?}", type_bit_maps);

        Ok(Self {
            hash_algorithm,
            flags,
            iterations,
            salt,
            next_hashed_owner_name,
            type_bit_maps,
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
            0x01,        // hash_algorithm
            0x00,        // flags
            0x00, 0x01,  // iterations
            0x04,        // salt_length
            0x11, 0x22, 0x33, 0x44,  // salt
            0x05,        // hash_length
            0xaa, 0xbb, 0xcc, 0xdd, 0xee,  // next_hashed_owner_name
            0x00, 0x01,  // type_bit_maps (2 bytes for example)
        ];

        assert_eq!(NSEC3::read(buf.len() as _, &mut Cursor::new(buf)).unwrap(),
                   NSEC3 {
                       hash_algorithm: 1,
                       flags: 0,
                       iterations: 1,
                       salt: vec![0x11, 0x22, 0x33, 0x44],
                       next_hashed_owner_name: vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee],
                       type_bit_maps: vec![0x00, 0x01],
                   });
    }

    #[test]
    fn record_empty() {
        assert_eq!(NSEC3::read(0, &mut Cursor::new(&[])),
                   Err(WireError::IO));
    }

    #[test]
    fn buffer_ends_abruptly() {
        let buf = &[
            0x01,  // hash_algorithm
        ];

        assert_eq!(NSEC3::read(20, &mut Cursor::new(buf)),
                   Err(WireError::IO));
    }
}
