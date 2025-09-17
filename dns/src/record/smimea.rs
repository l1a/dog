use log::*;

use crate::wire::*;


/// A **SMIMEA** record, which contains an association between an S/MIME certificate and a domain name.
///
/// # References
///
/// - [RFC 8162](https://tools.ietf.org/html/rfc8162) — Using Secure DNS to Associate Certificates with Domain Names for S/MIME
#[derive(PartialEq, Debug)]
pub struct SMIMEA {
    /// The certificate usage field indicates the provided association that will be used to match the certificate.
    pub certificate_usage: u8,

    /// The selector field specifies which part of the certificate will be matched against the certificate data.
    pub selector: u8,

    /// The matching type field specifies how the certificate data is presented.
    pub matching_type: u8,

    /// The certificate data to be matched.
    pub certificate_data: Vec<u8>,
}

impl Wire for SMIMEA {
    const NAME: &'static str = "SMIMEA";
    const RR_TYPE: u16 = 53;

    #[cfg_attr(feature = "with_mutagen", ::mutagen::mutate)]
    fn read(stated_length: u16, c: &mut Cursor<&[u8]>) -> Result<Self, WireError> {
        if stated_length < 3 {
            let mandated_length = MandatedLength::AtLeast(4);
            return Err(WireError::WrongRecordLength { stated_length, mandated_length });
        }

        let certificate_usage = c.read_u8()?;
        trace!("Parsed certificate_usage -> {:?}", certificate_usage);

        let selector = c.read_u8()?;
        trace!("Parsed selector -> {:?}", selector);

        let matching_type = c.read_u8()?;
        trace!("Parsed matching_type -> {:?}", matching_type);

        let certificate_data_length = stated_length - 3;
        let mut certificate_data = vec![0_u8; usize::from(certificate_data_length)];
        c.read_exact(&mut certificate_data)?;
        trace!("Parsed certificate_data -> {:#x?}", certificate_data);

        Ok(Self { certificate_usage, selector, matching_type, certificate_data })
    }
}


impl SMIMEA {

    /// Returns the hexadecimal representation of the certificate data.
    pub fn hex_certificate_data(&self) -> String {
        self.certificate_data.iter()
            .map(|byte| format!("{:02x}", byte))
            .collect()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn parses() {
        let buf = &[
            0x03,        // certificate_usage
            0x01,        // selector
            0x02,        // matching_type
            0x12, 0x34, 0x56, 0x78,  // certificate_data (4 bytes for example)
        ];

        assert_eq!(SMIMEA::read(buf.len() as _, &mut Cursor::new(buf)).unwrap(),
                   SMIMEA {
                       certificate_usage: 3,
                       selector: 1,
                       matching_type: 2,
                       certificate_data: vec![0x12, 0x34, 0x56, 0x78],
                   });
    }

    #[test]
    fn record_empty() {
        assert_eq!(SMIMEA::read(0, &mut Cursor::new(&[])),
                   Err(WireError::WrongRecordLength { stated_length: 0, mandated_length: MandatedLength::AtLeast(4) }));
    }

    #[test]
    fn record_too_short() {
        let buf = &[
            0x03,        // certificate_usage
            0x01,        // selector
        ];

        assert_eq!(SMIMEA::read(buf.len() as _, &mut Cursor::new(buf)),
                   Err(WireError::WrongRecordLength { stated_length: 2, mandated_length: MandatedLength::AtLeast(4) }));
    }

    #[test]
    fn buffer_ends_abruptly() {
        let buf = &[
            0x03,        // certificate_usage
            0x01,        // selector
            0x02,        // matching_type
        ];

        assert_eq!(SMIMEA::read(6, &mut Cursor::new(buf)),
                   Err(WireError::IO));
    }

    #[test]
    fn one_byte_certificate() {
        let buf = &[
            0x03,        // certificate_usage
            0x01,        // selector
            0x02,        // matching_type
            0x42,        // certificate_data (1 byte)
        ];

        assert_eq!(SMIMEA::read(buf.len() as _, &mut Cursor::new(buf)).unwrap(),
                   SMIMEA {
                       certificate_usage: 3,
                       selector: 1,
                       matching_type: 2,
                       certificate_data: vec![0x42],
                   });
    }
}
