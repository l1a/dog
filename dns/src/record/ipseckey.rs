use log::*;

use crate::wire::*;

/// A **IPSECKEY** record, which contains an IPsec key for the domain.
///
/// # References
///
/// - [RFC 4025](https://tools.ietf.org/html/rfc4025) — A Method for Storing IPsec Keying Material in DNS (February 2005)
#[derive(PartialEq, Debug)]
pub struct IPSECKEY {
    /// The precedence of this key.
    pub precedence: u8,

    /// The type of gateway.
    pub gateway_type: u8,

    /// The algorithm used for the public key.
    pub algorithm: u8,

    /// The gateway address or name.
    pub gateway: Vec<u8>,

    /// The public key.
    pub public_key: Vec<u8>,
}

impl Wire for IPSECKEY {
    const NAME: &'static str = "IPSECKEY";
    const RR_TYPE: u16 = 45;

    #[cfg_attr(feature = "with_mutagen", ::mutagen::mutate)]
    fn read(stated_length: u16, c: &mut Cursor<&[u8]>) -> Result<Self, WireError> {
        let precedence = c.read_u8()?;
        trace!("Parsed precedence -> {:?}", precedence);

        let gateway_type = c.read_u8()?;
        trace!("Parsed gateway_type -> {:?}", gateway_type);

        let algorithm = c.read_u8()?;
        trace!("Parsed algorithm -> {:?}", algorithm);

        let mut bytes_left = stated_length - 3;
        let gateway_len = match gateway_type {
            1 => 4,  // IPv4
            2 => 16, // IPv6
            3 => {
                // FQDN, need to read labels
                // But for simplicity, we'll read as Vec<u8> until null or something, but it's complicated
                // For this implementation, assume we read until the remaining is public key
                // Actually, for FQDN, it's a domain name followed by public key
                // To keep it simple, read as much as needed, but better to handle properly
                // For now, let's assume gateway is variable, but calculate based on type
                unimplemented!("FQDN gateway parsing not implemented yet");
            }
            _ => 0, // no gateway
        };
        let mut gateway = vec![];
        for _ in 0..gateway_len {
            gateway.push(c.read_u8()?);
            bytes_left -= 1;
        }
        trace!("Parsed gateway -> {:?}", gateway);

        let mut public_key = vec![];
        for _ in 0..bytes_left {
            public_key.push(c.read_u8()?);
        }
        trace!("Parsed public_key -> {:?}", public_key);

        Ok(Self { precedence, gateway_type, algorithm, gateway, public_key })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn parses() {
        let buf = &[
            0x01,        // precedence
            0x01,        // gateway_type (IPv4)
            0x05,        // algorithm
            0xc0, 0xa8, 0x00, 0x01,  // gateway IPv4: 192.168.0.1
            0x12, 0x34, 0x56, 0x78,  // public_key (4 bytes for example)
        ];

        assert_eq!(IPSECKEY::read(buf.len() as _, &mut Cursor::new(buf)).unwrap(),
                   IPSECKEY {
                       precedence: 1,
                       gateway_type: 1,
                       algorithm: 5,
                       gateway: vec![0xc0, 0xa8, 0x00, 0x01],
                       public_key: vec![0x12, 0x34, 0x56, 0x78],
                   });
    }

    #[test]
    fn record_empty() {
        assert_eq!(IPSECKEY::read(0, &mut Cursor::new(&[])),
                   Err(WireError::IO));
    }

    #[test]
    fn buffer_ends_abruptly() {
        let buf = &[
            0x01,  // precedence
        ];

        assert_eq!(IPSECKEY::read(10, &mut Cursor::new(buf)),
                   Err(WireError::IO));
    }
}
