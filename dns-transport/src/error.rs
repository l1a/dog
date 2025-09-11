/// Something that can go wrong making a DNS request.
#[derive(Debug)]
pub enum Error {

    /// The data in the response did not parse correctly from the DNS wire
    /// protocol format.
    WireError(dns::WireError),

    /// There was a problem with the network making a TCP or UDP request.
    NetworkError(std::io::Error),

    /// Not enough information was received from the server before a `read`
    /// call returned zero bytes.
    TruncatedResponse,

    /// An error from the TLS library.
    #[cfg(feature = "with_rustls")]
    RustlsError(rustls::Error),

    /// Provided dns name is not valid
    #[cfg(feature = "with_rustls")]
    RustlsInvalidDnsNameError(webpki::InvalidDnsNameError),

    /// Provided dns name is not valid
    #[cfg(feature = "with_rustls")]
    RustlsInvalidDnsNameError2(rustls::pki_types::InvalidDnsNameError),

    /// There was a problem decoding the response HTTP headers or body.
    #[cfg(feature = "with_https")]
    HttpError(httparse::Error),

    /// The HTTP response code was something other than 200 OK, along with the
    /// response code text, if present.
    #[cfg(feature = "with_https")]
    WrongHttpStatus(u16, Option<String>),
}


// From impls

impl From<dns::WireError> for Error {
    fn from(inner: dns::WireError) -> Self {
        Self::WireError(inner)
    }
}

impl From<std::io::Error> for Error {
    fn from(inner: std::io::Error) -> Self {
        Self::NetworkError(inner)
    }
}

#[cfg(feature = "with_rustls")]
impl From<rustls::Error> for Error {
    fn from(inner: rustls::Error) -> Self {
        Self::RustlsError(inner)
    }
}

#[cfg(feature = "with_rustls")]
impl From<webpki::InvalidDnsNameError> for Error {
    fn from(inner: webpki::InvalidDnsNameError) -> Self {
        Self::RustlsInvalidDnsNameError(inner)
    }
}

#[cfg(feature = "with_rustls")]
impl From<rustls::pki_types::InvalidDnsNameError> for Error {
    fn from(inner: rustls::pki_types::InvalidDnsNameError) -> Self {
        Self::RustlsInvalidDnsNameError2(inner)
    }
}

#[cfg(feature = "with_https")]
impl From<httparse::Error> for Error {
    fn from(inner: httparse::Error) -> Self {
        Self::HttpError(inner)
    }
}
